/*
 * DNS Filter - Сервис фильтрации DNS запросов
 * Маршрутизация DNS запросов на основе конфигурационных правил
 * С фильтрацией ответов по типам записей (множественные типы и исключения)
 * Поддержка IPv4 и IPv6
 */

#define _POSIX_C_SOURCE 200112L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netdb.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>

#define MAX_RULES 100
#define MAX_SERVERS 10
#define DNS_PORT 53
#define BUFFER_SIZE 512
#define CONFIG_FILE "dns_filter.conf"

// DNS типы записей
#define DNS_TYPE_A      1
#define DNS_TYPE_NS     2
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_MX     15
#define DNS_TYPE_AAAA   28

// Структура для фильтра типов
typedef struct {
    int ipv4;      // A
    int ipv6;      // AAAA
    int mx;        // MX
    int ns;        // NS
    int all;       // * (все)
    int exclude;   // Режим исключения (! перед типом)
} TypeFilter;

// Структура для правила маршрутизации
typedef struct {
    char pattern[128];           // Шаблон домена
    TypeFilter filter;          // Фильтр типов
    char servers[MAX_SERVERS][256]; // DNS серверы
    int server_count;           // Количество серверов
} DnsRule;

// Структура конфигурации
typedef struct {
    DnsRule rules[MAX_RULES];
    int rule_count;
    char default_servers[MAX_SERVERS][256];
    int default_server_count;
    int debug;  // Флаг отладки
} DnsConfig;

typedef struct {
    int socket;
    struct sockaddr_storage client_addr;  // Используем sockaddr_storage для IPv4/IPv6
    socklen_t client_addr_len;
    unsigned char buffer[BUFFER_SIZE];
    size_t buffer_len;
    TypeFilter *filter;  // Фильтр для применения
} QueryContext;

DnsConfig g_config;

// Вспомогательные функции

void debug_log(const char *fmt, ...) {
    if (!g_config.debug) return;

    va_list args;
    va_start(args, fmt);
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("[%s] DEBUG: ", timestamp);
    vprintf(fmt, args);
    fflush(stdout);
    va_end(args);
}

// Преобразование адреса в строку (IPv4 или IPv6)
const char* addr_to_string(struct sockaddr_storage *addr, char *buf, size_t buflen) {
    void *addr_ptr;

    if (addr->ss_family == AF_INET) {
        addr_ptr = &((struct sockaddr_in*)addr)->sin_addr;
    } else if (addr->ss_family == AF_INET6) {
        addr_ptr = &((struct sockaddr_in6*)addr)->sin6_addr;
    } else {
        snprintf(buf, buflen, "unknown");
        return buf;
    }

    return inet_ntop(addr->ss_family, addr_ptr, buf, buflen);
}

// Получить 16-битное значение из сетевого порядка байтов
uint16_t get_uint16(const unsigned char *data) {
    return (data[0] << 8) | data[1];
}

// Установить 16-битное значение в сетевом порядке байтов
void set_uint16(unsigned char *data, uint16_t value) {
    data[0] = (value >> 8) & 0xFF;
    data[1] = value & 0xFF;
}

// Проверка, нужна ли фильтрация
int needs_filtering(TypeFilter *filter) {
    if (!filter) return 0;
    if (filter->all && !filter->exclude) return 0;
    // Если установлен хотя бы один специфичный фильтр
    if (filter->ipv4 || filter->ipv6 || filter->mx || filter->ns) return 1;
    return 0;
}

// Проверка, должен ли тип записи быть отфильтрован
int should_filter_type(TypeFilter *filter, uint16_t qtype) {
    if (!filter || (filter->all && !filter->exclude)) return 0;  // Не фильтруем

    int is_selected = 0;

    switch (qtype) {
        case DNS_TYPE_A:
            is_selected = filter->ipv4;
            break;
        case DNS_TYPE_AAAA:
            is_selected = filter->ipv6;
            break;
        case DNS_TYPE_MX:
            is_selected = filter->mx;
            break;
        case DNS_TYPE_NS:
            is_selected = filter->ns;
            break;
        case DNS_TYPE_CNAME:
            return 0;  // CNAME всегда оставляем
        default:
            is_selected = 0;
            break;
    }

    // Если режим исключения - инвертируем логику
    if (filter->exclude) {
        // Исключаем если тип выбран
        return is_selected;
    } else {
        // Фильтруем если тип НЕ выбран
        return !is_selected;
    }
}

const char* type_to_string(uint16_t type) {
    switch (type) {
        case DNS_TYPE_A: return "A";
        case DNS_TYPE_NS: return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_MX: return "MX";
        case DNS_TYPE_AAAA: return "AAAA";
        default: return "UNKNOWN";
    }
}

// Пропустить DNS имя в пакете
int skip_dns_name(const unsigned char *buffer, size_t len, size_t *pos) {
    while (*pos < len) {
        unsigned char label_len = buffer[*pos];

        if (label_len == 0) {
            (*pos)++;
            return 0;
        }

        // Проверка на сжатие (compression pointer)
        if ((label_len & 0xC0) == 0xC0) {
            (*pos) += 2;
            return 0;
        }

        (*pos)++;
        *pos += label_len;
    }

    return -1;
}

// Фильтрация DNS ответа
size_t filter_dns_response(unsigned char *response, size_t response_len, TypeFilter *filter) {
    if (!needs_filtering(filter)) {
        debug_log("No filtering needed\n");
        return response_len;
    }

    if (response_len < 12) {
        debug_log("Response too short for filtering\n");
        return response_len;
    }

    debug_log("Filter mode: %s, flags: ipv4=%d ipv6=%d mx=%d ns=%d all=%d\n",
              filter->exclude ? "EXCLUDE" : "INCLUDE",
              filter->ipv4, filter->ipv6, filter->mx, filter->ns, filter->all);

    // Парсинг DNS заголовка
    uint16_t qdcount = get_uint16(response + 4);
    uint16_t ancount = get_uint16(response + 6);
    uint16_t nscount = get_uint16(response + 8);
    uint16_t arcount = get_uint16(response + 10);

    debug_log("Original counts: QD=%d AN=%d NS=%d AR=%d\n", qdcount, ancount, nscount, arcount);

    if (ancount == 0) {
        debug_log("No answers to filter\n");
        return response_len;
    }

    // Пропускаем Question section
    size_t pos = 12;
    for (int i = 0; i < qdcount; i++) {
        if (skip_dns_name(response, response_len, &pos) < 0) return response_len;
        pos += 4;  // QTYPE + QCLASS
    }

    // Создаём новый буфер для фильтрованного ответа
    unsigned char filtered[BUFFER_SIZE];
    memcpy(filtered, response, pos);  // Копируем заголовок и questions

    size_t write_pos = pos;
    uint16_t new_ancount = 0;

    // Обрабатываем Answer section
    for (int i = 0; i < ancount && pos < response_len; i++) {
        size_t record_start = pos;

        // Пропускаем имя
        if (skip_dns_name(response, response_len, &pos) < 0) break;

        if (pos + 10 > response_len) break;

        // Читаем TYPE, CLASS, TTL, RDLENGTH
        uint16_t rtype = get_uint16(response + pos);
        uint16_t rdlength = get_uint16(response + pos + 8);

        size_t record_len = (pos - record_start) + 10 + rdlength;

        // Проверяем фильтр
        if (should_filter_type(filter, rtype)) {
            debug_log("  ✗ Filtering out %s record\n", type_to_string(rtype));
            pos += 10 + rdlength;
            continue;
        }

        debug_log("  ✓ Keeping %s record\n", type_to_string(rtype));

        // Копируем запись
        if (write_pos + record_len <= BUFFER_SIZE) {
            memcpy(filtered + write_pos, response + record_start, record_len);
            write_pos += record_len;
            new_ancount++;
        }

        pos += 10 + rdlength;
    }

    // Копируем Authority и Additional sections как есть
    if (pos < response_len && write_pos < BUFFER_SIZE) {
        size_t remaining = response_len - pos;
        if (write_pos + remaining <= BUFFER_SIZE) {
            memcpy(filtered + write_pos, response + pos, remaining);
            write_pos += remaining;
        }
    }

    // Обновляем счётчик ответов
    set_uint16(filtered + 6, new_ancount);

    debug_log("Filtered result: AN=%d (was %d), size=%zu (was %zu)\n", 
              new_ancount, ancount, write_pos, response_len);

    // Копируем результат обратно
    memcpy(response, filtered, write_pos);
    return write_pos;
}

// Проверка соответствия доменного имени шаблону
int domain_matches(const char *domain, const char *pattern) {
    char domain_lower[256];
    char pattern_lower[256];
    size_t i;

    // Преобразование в нижний регистр
    for (i = 0; domain[i]; i++) {
        domain_lower[i] = tolower(domain[i]);
    }
    domain_lower[strlen(domain)] = '\0';

    for (i = 0; pattern[i]; i++) {
        pattern_lower[i] = tolower(pattern[i]);
    }
    pattern_lower[strlen(pattern)] = '\0';

    // Обработка wildcards
    if (strchr(pattern_lower, '*') == NULL) {
        return strcmp(domain_lower, pattern_lower) == 0;
    }

    char *star = strchr(pattern_lower, '*');
    size_t prefix_len = star - pattern_lower;
    size_t suffix_len = strlen(star + 1);

    if (strlen(domain_lower) < prefix_len + suffix_len) {
        return 0;
    }

    if (strncmp(domain_lower, pattern_lower, prefix_len) != 0) {
        return 0;
    }

    if (strcmp(domain_lower + strlen(domain_lower) - suffix_len, star + 1) != 0) {
        return 0;
    }

    return 1;
}

// Парсинг DNS пакета и извлечение доменного имени
int extract_domain(const unsigned char *buffer, size_t len, char *domain) {
    if (len < 12) return -1;

    size_t pos = 12;
    domain[0] = '\0';

    while (pos < len && buffer[pos] != 0) {
        unsigned char len_byte = buffer[pos++];

        if (len_byte >= 192) {
            pos++;
            break;
        }

        if (domain[0] != '\0') strcat(domain, ".");

        for (int i = 0; i < len_byte && pos < len; i++, pos++) {
            char c = buffer[pos];
            strncat(domain, &c, 1);
        }
    }

    return 0;
}

// Резолюция имени DNS сервера в IP
char* resolve_server(const char *server) {
    static char resolved_ip[INET6_ADDRSTRLEN];

    // Проверка, является ли это уже IP адресом (IPv4)
    struct in_addr test_addr4;
    if (inet_pton(AF_INET, server, &test_addr4) == 1) {
        strcpy(resolved_ip, server);
        return resolved_ip;
    }

    // Проверка IPv6
    struct in6_addr test_addr6;
    if (inet_pton(AF_INET6, server, &test_addr6) == 1) {
        strcpy(resolved_ip, server);
        return resolved_ip;
    }

    // Попытка резолюции по имени (предпочитаем IPv4)
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // Предпочитаем IPv4
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(server, NULL, &hints, &res) == 0) {
        if (res->ai_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr,
                     resolved_ip, sizeof(resolved_ip));
        } else if (res->ai_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)res->ai_addr)->sin6_addr,
                     resolved_ip, sizeof(resolved_ip));
        }
        debug_log("Resolved %s to %s\n", server, resolved_ip);
        freeaddrinfo(res);
        return resolved_ip;
    }

    debug_log("Failed to resolve %s\n", server);
    return NULL;
}

// Парсинг фильтра типов
int parse_filter(char *filter_str, TypeFilter *filter) {
    memset(filter, 0, sizeof(TypeFilter));

    char filter_copy[256];
    strncpy(filter_copy, filter_str, sizeof(filter_copy) - 1);
    filter_copy[sizeof(filter_copy) - 1] = '\0';

    // Удаляем пробелы в начале и конце
    char *start = filter_copy;
    while (*start == ' ') start++;

    char *end = start + strlen(start) - 1;
    while (end > start && *end == ' ') {
        *end = '\0';
        end--;
    }

    // Проверяем на '*' (все типы)
    if (strcmp(start, "*") == 0) {
        filter->all = 1;
        return 0;
    }

    // Парсим токены
    int has_exclude = 0;
    int has_include = 0;

    char *token = strtok(start, " ");
    while (token) {
        int is_exclude = 0;

        // Проверяем на '!'
        if (token[0] == '!') {
            is_exclude = 1;
            has_exclude = 1;
            token++; // Пропускаем '!'
        } else {
            has_include = 1;
        }

        // Проверка на смешивание режимов
        if (has_exclude && has_include) {
            fprintf(stderr, "ERROR: Cannot mix include and exclude filters\n");
            return -1;
        }

        // Устанавливаем флаг исключения
        if (is_exclude) {
            filter->exclude = 1;
        }

        // Парсим тип
        if (strcmp(token, "ipv4") == 0) {
            filter->ipv4 = 1;
        } else if (strcmp(token, "ipv6") == 0) {
            filter->ipv6 = 1;
        } else if (strcmp(token, "mx") == 0) {
            filter->mx = 1;
        } else if (strcmp(token, "ns") == 0) {
            filter->ns = 1;
        } else {
            fprintf(stderr, "WARNING: Unknown filter type: %s\n", token);
        }

        token = strtok(NULL, " ");
    }

    return 0;
}

// Форматирование фильтра для вывода
void format_filter(TypeFilter *filter, char *output, size_t output_size) {
    output[0] = '\0';

    if (filter->all && !filter->exclude) {
        strncpy(output, "all records (*)", output_size - 1);
        return;
    }

    if (filter->exclude) {
        strncat(output, "all EXCEPT: ", output_size - strlen(output) - 1);
    } else {
        strncat(output, "only: ", output_size - strlen(output) - 1);
    }

    int first = 1;
    if (filter->ipv4) {
        if (!first) strncat(output, ", ", output_size - strlen(output) - 1);
        strncat(output, "IPv4", output_size - strlen(output) - 1);
        first = 0;
    }
    if (filter->ipv6) {
        if (!first) strncat(output, ", ", output_size - strlen(output) - 1);
        strncat(output, "IPv6", output_size - strlen(output) - 1);
        first = 0;
    }
    if (filter->mx) {
        if (!first) strncat(output, ", ", output_size - strlen(output) - 1);
        strncat(output, "MX", output_size - strlen(output) - 1);
        first = 0;
    }
    if (filter->ns) {
        if (!first) strncat(output, ", ", output_size - strlen(output) - 1);
        strncat(output, "NS", output_size - strlen(output) - 1);
        first = 0;
    }
}

// Загрузка конфигурации из файла
int load_config(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (f == NULL) {
        perror("Cannot open config file");
        return -1;
    }

    char line[512];
    g_config.rule_count = 0;
    g_config.default_server_count = 0;
    g_config.debug = 0;

    while (fgets(line, sizeof(line), f)) {
        // Удаление пробелов и комментариев
        line[strcspn(line, "\n")] = 0;
        if (line[0] == '#' || line[0] == '\0') continue;

        char *ptr = line;
        while (*ptr == ' ') ptr++;

        if (strncmp(ptr, "debug", 5) == 0) {
            g_config.debug = 1;
            printf("Debug mode enabled\n");
            continue;
        }

        if (strncmp(ptr, "default:", 8) == 0) {
            char *servers = ptr + 8;
            char *token = strtok(servers, " ");

            while (token && g_config.default_server_count < MAX_SERVERS) {
                strcpy(g_config.default_servers[g_config.default_server_count++], token);
                token = strtok(NULL, " ");
            }
            continue;
        }

        if (strncmp(ptr, "rule:", 5) == 0 && g_config.rule_count < MAX_RULES) {
            DnsRule *rule = &g_config.rules[g_config.rule_count];
            memset(rule, 0, sizeof(DnsRule));

            char *pattern = ptr + 5;
            while (*pattern == ' ') pattern++;

            char *arrow1 = strstr(pattern, "->");
            if (!arrow1) continue;

            char *arrow2 = strstr(arrow1 + 2, "->");
            if (!arrow2) continue;

            size_t plen = arrow1 - pattern;
            strncpy(rule->pattern, pattern, plen);
            rule->pattern[plen] = '\0';

            // Удаление пробелов
            while (plen > 0 && rule->pattern[plen-1] == ' ') 
                rule->pattern[--plen] = '\0';

            // Парсинг фильтра типов
            char *filter_str = arrow1 + 2;
            char filter_buf[256];
            size_t filter_len = arrow2 - filter_str;
            strncpy(filter_buf, filter_str, filter_len);
            filter_buf[filter_len] = '\0';

            if (parse_filter(filter_buf, &rule->filter) < 0) {
                fprintf(stderr, "ERROR: Invalid filter in rule %d\n", g_config.rule_count + 1);
                continue;
            }

            // Форматируем фильтр для вывода
            char filter_desc[256];
            format_filter(&rule->filter, filter_desc, sizeof(filter_desc));
            printf("Rule '%s': %s\n", rule->pattern, filter_desc);

            // Парсинг серверов
            char *servers = arrow2 + 2;
            while (*servers == ' ') servers++;

            char servers_copy[256];
            strcpy(servers_copy, servers);

            char *token = strtok(servers_copy, " ");
            rule->server_count = 0;

            while (token && rule->server_count < MAX_SERVERS) {
                strcpy(rule->servers[rule->server_count++], token);
                token = strtok(NULL, " ");
            }

            g_config.rule_count++;
        }
    }

    fclose(f);
    printf("Loaded %d rules, %d default servers\n", 
           g_config.rule_count, g_config.default_server_count);

    return 0;
}

// Отправка DNS запроса на upstream сервер
int forward_query(const char *server_ip, 
                  const unsigned char *query, 
                  size_t query_len,
                  unsigned char *response, 
                  size_t *response_len) {

    // Определяем тип адреса (IPv4 или IPv6)
    struct sockaddr_storage server_addr;
    socklen_t server_addr_len;
    int af_family;

    memset(&server_addr, 0, sizeof(server_addr));

    // Пробуем IPv4
    struct sockaddr_in *addr4 = (struct sockaddr_in*)&server_addr;
    if (inet_pton(AF_INET, server_ip, &addr4->sin_addr) == 1) {
        af_family = AF_INET;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(53);
        server_addr_len = sizeof(struct sockaddr_in);
    } 
    // Пробуем IPv6
    else {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)&server_addr;
        if (inet_pton(AF_INET6, server_ip, &addr6->sin6_addr) == 1) {
            af_family = AF_INET6;
            addr6->sin6_family = AF_INET6;
            addr6->sin6_port = htons(53);
            server_addr_len = sizeof(struct sockaddr_in6);
        } else {
            fprintf(stderr, "Invalid server IP: %s\n", server_ip);
            return -1;
        }
    }

    int sock = socket(af_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (sendto(sock, query, query_len, 0, 
               (struct sockaddr *)&server_addr, server_addr_len) < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }

    struct sockaddr_storage from;
    socklen_t from_len = sizeof(from);

    ssize_t n = recvfrom(sock, response, BUFFER_SIZE, 0, 
                          (struct sockaddr *)&from, &from_len);

    if (n < 0) {
        perror("recvfrom");
        close(sock);
        return -1;
    }

    *response_len = n;
    close(sock);

    return 0;
}

// Обработка DNS запроса в отдельном потоке
void* handle_query(void *arg) {
    QueryContext *ctx = (QueryContext *)arg;

    char domain[256];
    if (extract_domain(ctx->buffer, ctx->buffer_len, domain) < 0) {
        debug_log("Failed to extract domain\n");
        free(ctx);
        return NULL;
    }

    char client_ip[INET6_ADDRSTRLEN];
    addr_to_string(&ctx->client_addr, client_ip, sizeof(client_ip));

    printf("Query for: %s from %s\n", domain, client_ip);
    debug_log("Received query for domain: %s from %s\n", domain, client_ip);

    // Поиск подходящего правила
    DnsRule *matched_rule = NULL;
    for (int i = 0; i < g_config.rule_count; i++) {
        if (domain_matches(domain, g_config.rules[i].pattern)) {
            matched_rule = &g_config.rules[i];
            debug_log("Matched rule: %s\n", matched_rule->pattern);
            break;
        }
    }

    // Выбор серверов и фильтра
    int server_count = 0;
    char (*servers)[256] = NULL;
    TypeFilter *filter = NULL;

    if (matched_rule) {
        server_count = matched_rule->server_count;
        servers = matched_rule->servers;
        filter = &matched_rule->filter;
        debug_log("Using %d servers from rule\n", server_count);
    } else {
        server_count = g_config.default_server_count;
        servers = g_config.default_servers;
        filter = NULL;  // Нет фильтрации для default
        debug_log("Using %d default servers\n", server_count);
    }

    // Попытка отправить запрос на каждый сервер
    unsigned char response[BUFFER_SIZE];
    size_t response_len = 0;
    int success = 0;

    for (int i = 0; i < server_count; i++) {
        char *server_ip = resolve_server(servers[i]);

        if (server_ip == NULL) {
            debug_log("Cannot resolve %s, trying next\n", servers[i]);
            continue;
        }

        debug_log("Forwarding to %s (%s)\n", servers[i], server_ip);

        if (forward_query(server_ip, ctx->buffer, ctx->buffer_len, 
                            response, &response_len) == 0) {
            success = 1;
            break;
        }
    }

    // Применяем фильтр к ответу
    if (success && needs_filtering(filter)) {
        debug_log("Applying filter to response...\n");
        response_len = filter_dns_response(response, response_len, filter);
    }

    // Отправка ответа клиенту
    if (success) {
        sendto(ctx->socket, response, response_len, 0,
               (struct sockaddr *)&ctx->client_addr, ctx->client_addr_len);
        debug_log("Response sent (%zu bytes)\n", response_len);
    } else {
        debug_log("All upstream servers failed\n");
    }

    free(ctx);
    return NULL;
}

// Создание и привязка сокета (IPv4 или IPv6)
int create_and_bind_socket(int af_family) {
    int sock = socket(af_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (af_family == AF_INET6) {
        // Отключаем dual-stack (чтобы IPv6 сокет не принимал IPv4)
        int v6only = 1;
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    }

    struct sockaddr_storage addr;
    socklen_t addr_len;
    memset(&addr, 0, sizeof(addr));

    if (af_family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in*)&addr;
        addr4->sin_family = AF_INET;
        addr4->sin_addr.s_addr = htonl(INADDR_ANY);
        addr4->sin_port = htons(DNS_PORT);
        addr_len = sizeof(struct sockaddr_in);
    } else {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)&addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_addr = in6addr_any;
        addr6->sin6_port = htons(DNS_PORT);
        addr_len = sizeof(struct sockaddr_in6);
    }

    if (bind(sock, (struct sockaddr *)&addr, addr_len) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    return sock;
}

// Основной цикл сервера
int main(int argc, char *argv[]) {
    int sock4, sock6;

    // Игнорируем неиспользуемый argc
    (void)argc;
    (void)argv;

    // Инициализация конфигурации
    memset(&g_config, 0, sizeof(g_config));

    // Загрузка конфигурации
    if (load_config(CONFIG_FILE) < 0) {
        fprintf(stderr, "Using default configuration\n");
        strcpy(g_config.default_servers[0], "8.8.8.8");
        g_config.default_server_count = 1;
    }

    // Создание IPv4 сокета
    sock4 = create_and_bind_socket(AF_INET);
    if (sock4 < 0) {
        fprintf(stderr, "Failed to create IPv4 socket\n");
        return 1;
    }
    printf("DNS Filter listening on 0.0.0.0:%d (IPv4)\n", DNS_PORT);

    // Создание IPv6 сокета
    sock6 = create_and_bind_socket(AF_INET6);
    if (sock6 < 0) {
        fprintf(stderr, "Warning: Failed to create IPv6 socket (IPv6 disabled)\n");
        sock6 = -1;
    } else {
        printf("DNS Filter listening on [::]:%d (IPv6)\n", DNS_PORT);
    }

    if (g_config.debug) {
        printf("Debug mode: ON\n");
    }

    // Основной цикл с select()
    fd_set readfds;
    int maxfd = (sock6 > sock4) ? sock6 : sock4;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sock4, &readfds);
        if (sock6 >= 0) {
            FD_SET(sock6, &readfds);
        }

        int activity = select(maxfd + 1, &readfds, NULL, NULL, NULL);

        if (activity < 0) {
            perror("select");
            continue;
        }

        // Проверяем IPv4 сокет
        if (FD_ISSET(sock4, &readfds)) {
            QueryContext *ctx = malloc(sizeof(QueryContext));
            if (!ctx) {
                perror("malloc");
                continue;
            }

            ctx->socket = sock4;
            ctx->client_addr_len = sizeof(ctx->client_addr);

            ssize_t n = recvfrom(sock4, ctx->buffer, BUFFER_SIZE, 0,
                                (struct sockaddr *)&ctx->client_addr, &ctx->client_addr_len);

            if (n < 0) {
                perror("recvfrom IPv4");
                free(ctx);
            } else {
                ctx->buffer_len = n;

                pthread_t thread;
                if (pthread_create(&thread, NULL, handle_query, ctx) != 0) {
                    perror("pthread_create");
                    free(ctx);
                } else {
                    pthread_detach(thread);
                }
            }
        }

        // Проверяем IPv6 сокет
        if (sock6 >= 0 && FD_ISSET(sock6, &readfds)) {
            QueryContext *ctx = malloc(sizeof(QueryContext));
            if (!ctx) {
                perror("malloc");
                continue;
            }

            ctx->socket = sock6;
            ctx->client_addr_len = sizeof(ctx->client_addr);

            ssize_t n = recvfrom(sock6, ctx->buffer, BUFFER_SIZE, 0,
                                (struct sockaddr *)&ctx->client_addr, &ctx->client_addr_len);

            if (n < 0) {
                perror("recvfrom IPv6");
                free(ctx);
            } else {
                ctx->buffer_len = n;

                pthread_t thread;
                if (pthread_create(&thread, NULL, handle_query, ctx) != 0) {
                    perror("pthread_create");
                    free(ctx);
                } else {
                    pthread_detach(thread);
                }
            }
        }
    }

    close(sock4);
    if (sock6 >= 0) close(sock6);
    return 0;
}
