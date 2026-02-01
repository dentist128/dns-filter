/*
 * DNS Filter - Сервис фильтрации DNS запросов
 * Graceful shutdown с обработкой сигналов SIGINT, SIGTERM, SIGQUIT
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
#include <signal.h>
#include <errno.h>

#define MAX_RULES 100
#define MAX_SERVERS 10
#define DNS_PORT 53
#define BUFFER_SIZE 512
#define CONFIG_FILE "dns_filter.conf"
#define SHUTDOWN_TIMEOUT 5

// DNS типы записей
#define DNS_TYPE_A      1
#define DNS_TYPE_NS     2
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_MX     15
#define DNS_TYPE_AAAA   28

volatile sig_atomic_t shutdown_flag = 0;
int sock4 = -1, sock6 = -1;

typedef struct {
    int ipv4, ipv6, mx, ns, all, exclude;
} TypeFilter;

typedef struct {
    char pattern[128];
    TypeFilter filter;
    char servers[MAX_SERVERS][256];
    int server_count;
} DnsRule;

typedef struct {
    DnsRule rules[MAX_RULES];
    int rule_count;
    char default_servers[MAX_SERVERS][256];
    int default_server_count;
    int debug;
} DnsConfig;

typedef struct {
    int socket;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    unsigned char buffer[BUFFER_SIZE];
    size_t buffer_len;
    TypeFilter *filter;
} QueryContext;

DnsConfig g_config;

static void signal_handler(int sig) {
    if (!shutdown_flag) {
        printf("\nReceived signal %d. Initiating graceful shutdown...\n", sig);
        fflush(stdout);
        shutdown_flag = 1;
    }
}

static void cleanup(void) {
    printf("Shutting down DNS Filter...\n");

    if (sock4 >= 0) {
        close(sock4);
        printf("IPv4 socket closed\n");
    }

    if (sock6 >= 0) {
        close(sock6);
        printf("IPv6 socket closed\n");
    }

    printf("DNS Filter stopped.\n");
    fflush(stdout);
}

void debug_log(const char *fmt, ...) {
    if (!g_config.debug || shutdown_flag) return;

    va_list args;
    va_start(args, fmt);
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

    printf("[%s] DEBUG: ", timestamp);
    vprintf(fmt, args);
    fflush(stdout);
    va_end(args);
}

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

uint16_t get_uint16(const unsigned char *data) {
    return (data[0] << 8) | data[1];
}

void set_uint16(unsigned char *data, uint16_t value) {
    data[0] = (value >> 8) & 0xFF;
    data[1] = value & 0xFF;
}

int needs_filtering(TypeFilter *filter) {
    if (!filter || shutdown_flag) return 0;
    if (filter->all && !filter->exclude) return 0;
    return filter->ipv4 || filter->ipv6 || filter->mx || filter->ns;
}

int should_filter_type(TypeFilter *filter, uint16_t qtype) {
    if (!filter || shutdown_flag) return 0;

    int is_selected = 0;
    switch (qtype) {
        case DNS_TYPE_A:    is_selected = filter->ipv4; break;
        case DNS_TYPE_AAAA: is_selected = filter->ipv6; break;
        case DNS_TYPE_MX:   is_selected = filter->mx;   break;
        case DNS_TYPE_NS:   is_selected = filter->ns;   break;
        case DNS_TYPE_CNAME: return 0;
        default: return 0;
    }

    return filter->exclude ? is_selected : !is_selected;
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

int skip_dns_name(const unsigned char *buffer, size_t len, size_t *pos) {
    while (*pos < len) {
        unsigned char label_len = buffer[*pos];

        if (label_len == 0) {
            (*pos)++;
            return 0;
        }

        if ((label_len & 0xC0) == 0xC0) {
            (*pos) += 2;
            return 0;
        }

        (*pos)++;
        *pos += label_len;
    }
    return -1;
}

size_t filter_dns_response(unsigned char *response, size_t response_len, TypeFilter *filter) {
    if (!needs_filtering(filter)) return response_len;

    if (response_len < 12) return response_len;

    uint16_t qdcount = get_uint16(response + 4);
    uint16_t ancount = get_uint16(response + 6);

    debug_log("Original AN=%d\n", ancount);

    if (ancount == 0) return response_len;

    size_t pos = 12;
    for (int i = 0; i < qdcount; i++) {
        if (skip_dns_name(response, response_len, &pos) < 0) return response_len;
        pos += 4;
    }

    unsigned char filtered[BUFFER_SIZE];
    memcpy(filtered, response, pos);

    size_t write_pos = pos;
    uint16_t new_ancount = 0;

    for (int i = 0; i < ancount && pos < response_len; i++) {
        size_t record_start = pos;

        if (skip_dns_name(response, response_len, &pos) < 0) break;

        if (pos + 10 > response_len) break;

        uint16_t rtype = get_uint16(response + pos);
        uint16_t rdlength = get_uint16(response + pos + 8);

        size_t record_len = (pos - record_start) + 10 + rdlength;

        if (should_filter_type(filter, rtype)) {
            debug_log("  ✗ Filter %s\n", type_to_string(rtype));
            pos += 10 + rdlength;
            continue;
        }

        debug_log("  ✓ Keep %s\n", type_to_string(rtype));

        if (write_pos + record_len <= BUFFER_SIZE) {
            memcpy(filtered + write_pos, response + record_start, record_len);
            write_pos += record_len;
            new_ancount++;
        }

        pos += 10 + rdlength;
    }

    if (pos < response_len && write_pos < BUFFER_SIZE) {
        size_t remaining = response_len - pos;
        if (write_pos + remaining <= BUFFER_SIZE) {
            memcpy(filtered + write_pos, response + pos, remaining);
            write_pos += remaining;
        }
    }

    set_uint16(filtered + 6, new_ancount);
    memcpy(response, filtered, write_pos);

    debug_log("Filtered AN=%d, size=%zu\n", new_ancount, write_pos);
    return write_pos;
}

int domain_matches(const char *domain, const char *pattern) {
    char domain_lower[256], pattern_lower[256];

    for (size_t i = 0; domain[i]; i++) domain_lower[i] = tolower(domain[i]);
    domain_lower[strlen(domain)] = '\0';

    for (size_t i = 0; pattern[i]; i++) pattern_lower[i] = tolower(pattern[i]);
    pattern_lower[strlen(pattern)] = '\0';

    if (!strchr(pattern_lower, '*')) return strcmp(domain_lower, pattern_lower) == 0;

    char *star = strchr(pattern_lower, '*');
    size_t prefix_len = star - pattern_lower;
    size_t suffix_len = strlen(star + 1);

    if (strlen(domain_lower) < prefix_len + suffix_len) return 0;

    if (strncmp(domain_lower, pattern_lower, prefix_len) != 0) return 0;
    if (strcmp(domain_lower + strlen(domain_lower) - suffix_len, star + 1) != 0) return 0;

    return 1;
}

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

        if (domain[0]) strcat(domain, ".");

        for (int i = 0; i < len_byte && pos < len; i++, pos++) {
            char c = buffer[pos];
            strncat(domain, &c, 1);
        }
    }

    return 0;
}

char* resolve_server(const char *server) {
    static char resolved_ip[INET6_ADDRSTRLEN];

    struct in_addr test_addr4;
    if (inet_pton(AF_INET, server, &test_addr4) == 1) {
        strcpy(resolved_ip, server);
        return resolved_ip;
    }

    struct in6_addr test_addr6;
    if (inet_pton(AF_INET6, server, &test_addr6) == 1) {
        strcpy(resolved_ip, server);
        return resolved_ip;
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(server, NULL, &hints, &res) == 0) {
        if (res->ai_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr,
                     resolved_ip, sizeof(resolved_ip));
        } else if (res->ai_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)res->ai_addr)->sin6_addr,
                     resolved_ip, sizeof(resolved_ip));
        }
        debug_log("Resolved %s → %s\n", server, resolved_ip);
        freeaddrinfo(res);
        return resolved_ip;
    }

    debug_log("Failed to resolve %s\n", server);
    return NULL;
}

int parse_filter(char *filter_str, TypeFilter *filter) {
    memset(filter, 0, sizeof(TypeFilter));

    char filter_copy[256];
    strncpy(filter_copy, filter_str, sizeof(filter_copy) - 1);
    filter_copy[sizeof(filter_copy) - 1] = '\0';

    char *start = filter_copy;
    while (*start == ' ') start++;
    char *end = start + strlen(start) - 1;
    while (end > start && *end == ' ') *end-- = '\0';

    if (strcmp(start, "*") == 0) {
        filter->all = 1;
        return 0;
    }

    int has_exclude = 0, has_include = 0;

    char *token = strtok(start, " ");
    while (token) {
        int is_exclude = 0;

        if (token[0] == '!') {
            is_exclude = 1;
            has_exclude = 1;
            token++;
        } else {
            has_include = 1;
        }

        if (has_exclude && has_include) {
            fprintf(stderr, "ERROR: Cannot mix include/exclude filters\n");
            return -1;
        }

        if (is_exclude) filter->exclude = 1;

        if (strcmp(token, "ipv4") == 0) filter->ipv4 = 1;
        else if (strcmp(token, "ipv6") == 0) filter->ipv6 = 1;
        else if (strcmp(token, "mx") == 0) filter->mx = 1;
        else if (strcmp(token, "ns") == 0) filter->ns = 1;
        else fprintf(stderr, "WARNING: Unknown filter: %s\n", token);

        token = strtok(NULL, " ");
    }

    return 0;
}

void format_filter(TypeFilter *filter, char *output, size_t output_size) {
    output[0] = '\0';

    if (filter->all && !filter->exclude) {
        strncpy(output, "all records (*)", output_size - 1);
        return;
    }

    if (filter->exclude) strncat(output, "all EXCEPT: ", output_size - strlen(output) - 1);
    else strncat(output, "only: ", output_size - strlen(output) - 1);

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

int load_config(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("Cannot open config file");
        return -1;
    }

    char line[512];
    g_config.rule_count = 0;
    g_config.default_server_count = 0;
    g_config.debug = 0;

    while (fgets(line, sizeof(line), f)) {
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

            while (plen > 0 && rule->pattern[plen-1] == ' ') rule->pattern[--plen] = '\0';

            char filter_buf[256];
            size_t filter_len = arrow2 - (arrow1 + 2);
            strncpy(filter_buf, arrow1 + 2, filter_len);
            filter_buf[filter_len] = '\0';

            if (parse_filter(filter_buf, &rule->filter) < 0) {
                fprintf(stderr, "ERROR: Invalid filter in rule %d\n", g_config.rule_count + 1);
                continue;
            }

            char filter_desc[256];
            format_filter(&rule->filter, filter_desc, sizeof(filter_desc));
            printf("Rule '%s': %s\n", rule->pattern, filter_desc);

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

int forward_query(const char *server_ip, const unsigned char *query, size_t query_len,
                  unsigned char *response, size_t *response_len) {

    struct sockaddr_storage server_addr;
    socklen_t server_addr_len;
    int af_family;

    memset(&server_addr, 0, sizeof(server_addr));

    struct sockaddr_in *addr4 = (struct sockaddr_in*)&server_addr;
    if (inet_pton(AF_INET, server_ip, &addr4->sin_addr) == 1) {
        af_family = AF_INET;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(53);
        server_addr_len = sizeof(struct sockaddr_in);
    } else {
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

    if (sendto(sock, query, query_len, 0, (struct sockaddr *)&server_addr, server_addr_len) < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }

    struct sockaddr_storage from;
    socklen_t from_len = sizeof(from);

    ssize_t n = recvfrom(sock, response, BUFFER_SIZE, 0, (struct sockaddr *)&from, &from_len);

    if (n < 0) {
        perror("recvfrom");
        close(sock);
        return -1;
    }

    *response_len = n;
    close(sock);

    return 0;
}

void* handle_query(void *arg) {
    QueryContext *ctx = (QueryContext *)arg;

    if (shutdown_flag) {
        free(ctx);
        return NULL;
    }

    char domain[256];
    if (extract_domain(ctx->buffer, ctx->buffer_len, domain) < 0) {
        debug_log("Failed to extract domain\n");
        free(ctx);
        return NULL;
    }

    char client_ip[INET6_ADDRSTRLEN];
    addr_to_string(&ctx->client_addr, client_ip, sizeof(client_ip));

    printf("Query for: %s from %s\n", domain, client_ip);

    DnsRule *matched_rule = NULL;
    for (int i = 0; i < g_config.rule_count; i++) {
        if (domain_matches(domain, g_config.rules[i].pattern)) {
            matched_rule = &g_config.rules[i];
            debug_log("Matched rule: %s\n", matched_rule->pattern);
            break;
        }
    }

    int server_count = 0;
    char (*servers)[256] = NULL;
    TypeFilter *filter = NULL;

    if (matched_rule) {
        server_count = matched_rule->server_count;
        servers = matched_rule->servers;
        filter = &matched_rule->filter;
    } else {
        server_count = g_config.default_server_count;
        servers = g_config.default_servers;
        filter = NULL;
    }

    unsigned char response[BUFFER_SIZE];
    size_t response_len = 0;
    int success = 0;

    for (int i = 0; i < server_count && !shutdown_flag; i++) {
        char *server_ip = resolve_server(servers[i]);

        if (!server_ip) {
            debug_log("Cannot resolve %s\n", servers[i]);
            continue;
        }

        debug_log("Forwarding to %s (%s)\n", servers[i], server_ip);

        if (forward_query(server_ip, ctx->buffer, ctx->buffer_len, response, &response_len) == 0) {
            success = 1;
            break;
        }
    }

    if (success && needs_filtering(filter)) {
        debug_log("Applying filter...\n");
        response_len = filter_dns_response(response, response_len, filter);
    }

    if (success && !shutdown_flag) {
        sendto(ctx->socket, response, response_len, 0,
               (struct sockaddr *)&ctx->client_addr, ctx->client_addr_len);
    }

    free(ctx);
    return NULL;
}

int create_and_bind_socket(int af_family) {
    int sock = socket(af_family, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (af_family == AF_INET6) {
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
        close(sock);
        return -1;
    }

    return sock;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    sock4 = sock6 = -1;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    atexit(cleanup);

    memset(&g_config, 0, sizeof(g_config));

    if (load_config(CONFIG_FILE) < 0) {
        fprintf(stderr, "Using default configuration\n");
        strcpy(g_config.default_servers[0], "8.8.8.8");
        g_config.default_server_count = 1;
    }

    sock4 = create_and_bind_socket(AF_INET);
    if (sock4 < 0) {
        fprintf(stderr, "Failed to create IPv4 socket\n");
        return 1;
    }
    printf("DNS Filter listening on 0.0.0.0:%d (IPv4)\n", DNS_PORT);

    sock6 = create_and_bind_socket(AF_INET6);
    if (sock6 < 0) {
        fprintf(stderr, "Warning: IPv6 socket failed (IPv6 disabled)\n");
    } else {
        printf("DNS Filter listening on [::]:%d (IPv6)\n", DNS_PORT);
    }

    if (g_config.debug) printf("Debug mode: ON\n");

    printf("Press Ctrl+C for graceful shutdown\n");

    fd_set readfds;
    int maxfd = (sock6 > sock4) ? sock6 : sock4;

    while (!shutdown_flag) {
        FD_ZERO(&readfds);
        FD_SET(sock4, &readfds);
        if (sock6 >= 0) FD_SET(sock6, &readfds);

        struct timeval timeout = {1, 0};

        int activity = select(maxfd + 1, &readfds, NULL, NULL, &timeout);

        if (activity < 0) {
            if (errno == EINTR) continue;
            perror("select");
            continue;
        }

        if (FD_ISSET(sock4, &readfds)) {
            QueryContext *ctx = malloc(sizeof(QueryContext));
            if (!ctx) continue;

            ctx->socket = sock4;
            ctx->client_addr_len = sizeof(ctx->client_addr);

            ssize_t n = recvfrom(sock4, ctx->buffer, BUFFER_SIZE, 0,
                                (struct sockaddr *)&ctx->client_addr, &ctx->client_addr_len);

            if (n > 0) {
                ctx->buffer_len = n;

                pthread_t thread;
                if (pthread_create(&thread, NULL, handle_query, ctx) == 0) {
                    pthread_detach(thread);
                } else {
                    free(ctx);
                }
            } else {
                free(ctx);
            }
        }

        if (sock6 >= 0 && FD_ISSET(sock6, &readfds)) {
            QueryContext *ctx = malloc(sizeof(QueryContext));
            if (!ctx) continue;

            ctx->socket = sock6;
            ctx->client_addr_len = sizeof(ctx->client_addr);

            ssize_t n = recvfrom(sock6, ctx->buffer, BUFFER_SIZE, 0,
                                (struct sockaddr *)&ctx->client_addr, &ctx->client_addr_len);

            if (n > 0) {
                ctx->buffer_len = n;

                pthread_t thread;
                if (pthread_create(&thread, NULL, handle_query, ctx) == 0) {
                    pthread_detach(thread);
                } else {
                    free(ctx);
                }
            } else {
                free(ctx);
            }
        }
    }

    printf("Waiting for active requests to complete (%ds timeout)...\n", SHUTDOWN_TIMEOUT);

    time_t start_time = time(NULL);
    while ((time(NULL) - start_time) < SHUTDOWN_TIMEOUT) {
        usleep(100000);  // 0.1s
    }

    cleanup();
    return 0;
}
