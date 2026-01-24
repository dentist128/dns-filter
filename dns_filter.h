/*
 * DNS Proxy Header - Структуры и функции
 */

// Дополнительные утилиты и функции

// Логирование с временной меткой
void log_timestamp() {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    printf("[%04d-%02d-%02d %02d:%02d:%02d] ",
           tm_info->tm_year + 1900,
           tm_info->tm_mon + 1,
           tm_info->tm_mday,
           tm_info->tm_hour,
           tm_info->tm_min,
           tm_info->tm_sec);
}

// Преобразование типа записи в строку
const char* qtype_to_string(int qtype) {
    switch (qtype) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 15: return "MX";
        case 28: return "AAAA";
        default: return "UNKNOWN";
    }
}

// Фильтрация ответа по типам записей
int should_filter(TypeFilter filter, int qtype) {
    if (filter.all) return 0; // Не фильтровать
    
    switch (qtype) {
        case 1: return !filter.ipv4;
        case 28: return !filter.ipv6;
        case 15: return !filter.mx;
        case 2: return !filter.ns;
        default: return 1;
    }
}

// Форматированный вывод конфигурации
void print_config(DnsConfig *config) {
    printf("\n=== DNS Proxy Configuration ===\n");
    printf("Rules count: %d\n", config->rule_count);
    
    for (int i = 0; i < config->rule_count; i++) {
        DnsRule *rule = &config->rules[i];
        printf("\nRule %d:\n", i + 1);
        printf("  Pattern: %s\n", rule->pattern);
        printf("  Servers: ");
        for (int j = 0; j < rule->server_count; j++) {
            printf("%s ", rule->servers[j]);
        }
        printf("\n");
    }
    
    printf("\nDefault servers: ");
    for (int i = 0; i < config->default_server_count; i++) {
        printf("%s ", config->default_servers[i]);
    }
    printf("\n\n");
}
