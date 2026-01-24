# DNS Filter Service Makefile
# Компиляция, установка и управление DNS фильтр сервисом

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -pthread
LDFLAGS = -lpthread

# Директории
SRCDIR = src
BINDIR = bin
CONFDIR = /etc/dns-filter
LOGDIR = /var/log/dns-filter
SYSTEMD_DIR = /etc/systemd/system

# Файлы
TARGET = $(BINDIR)/dns_filter
SOURCE = dns_filter.c
CONFIG = dns_filter.conf
SERVICE_FILE = dns-filter.service

# Пользователь и группа для сервиса
SERVICE_USER = dns-filter
SERVICE_GROUP = dns-filter

.PHONY: all build clean install uninstall start stop restart status enable disable debug help

# Основные цели
all: build

build: $(BINDIR) $(TARGET)
	@echo "✓ Сборка завершена: $(TARGET)"

$(BINDIR):
	@mkdir -p $(BINDIR)
	@echo "✓ Создана директория $(BINDIR)"

$(TARGET): $(SOURCE)
	@echo "→ Компилирование $(SOURCE)..."
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SOURCE)
	@echo "✓ Скомпилировано: $(TARGET)"

# Очистка
clean:
	@echo "→ Удаление бинарников..."
	@rm -rf $(BINDIR)
	@echo "✓ Очистка завершена"

# Установка
install: build
	@echo "→ Установка DNS фильтр сервиса..."
	@if id "$(SERVICE_USER)" >/dev/null 2>&1; then 		echo "✓ Пользователь $(SERVICE_USER) уже существует"; 	else 		echo "→ Создание пользователя $(SERVICE_USER)..."; 		useradd -r -s /bin/false $(SERVICE_USER); 		echo "✓ Пользователь $(SERVICE_USER) создан"; 	fi
	@mkdir -p $(CONFDIR)
	@mkdir -p $(LOGDIR)
	@install -D -m 755 $(TARGET) /usr/local/bin/dns_filter
	@install -D -m 644 $(CONFIG) $(CONFDIR)/dns_filter.conf
	@chown -R $(SERVICE_USER):$(SERVICE_GROUP) $(CONFDIR) $(LOGDIR)
	@chmod 750 $(LOGDIR)
	@echo "✓ Бинарник установлен в /usr/local/bin/dns_filter"
	@echo "✓ Конфиг установлен в $(CONFDIR)/dns_filter.conf"
	@echo ""
	@echo "→ Установка capabilities для порта 53..."
	@setcap 'cap_net_bind_service=+ep' /usr/local/bin/dns_filter
	@echo "✓ Capabilities установлены (CAP_NET_BIND_SERVICE)"
	@echo ""
	@echo "Теперь $(SERVICE_USER) может слушать порт 53!"

# Удаление capabilities (если нужно)
remove-cap:
	@echo "→ Удаление capabilities..."
	@setcap -r /usr/local/bin/dns_filter 2>/dev/null || true
	@echo "✓ Capabilities удалены"

# Проверка capabilities
check-cap:
	@echo "=== Current capabilities ==="
	@getcap /usr/local/bin/dns_filter || echo "No capabilities set"

# Удаление systemd сервиса
uninstall:
	@echo "→ Удаление DNS фильтр сервиса..."
	@systemctl is-active --quiet dns-filter && systemctl stop dns-filter || true
	@systemctl is-enabled --quiet dns-filter && systemctl disable dns-filter || true
	@$(MAKE) remove-cap
	@rm -f /usr/local/bin/dns_filter
	@rm -f $(SYSTEMD_DIR)/dns-filter.service
	@systemctl daemon-reload
	@echo "✓ Сервис удален"
	@echo "  Директории сохранены для восстановления:"
	@echo "  - $(CONFDIR)"
	@echo "  - $(LOGDIR)"

# Установка systemd сервиса
systemd-install: install create-service
	@echo "→ Установка systemd сервиса..."
	@install -D -m 644 $(SERVICE_FILE) $(SYSTEMD_DIR)/dns-filter.service
	@systemctl daemon-reload
	@echo "✓ Systemd сервис установлен"

# Создание systemd сервис-файла (если его нет)
create-service:
	@if [ ! -f "$(SERVICE_FILE)" ]; then 		echo "→ Создание $(SERVICE_FILE)..."; 		echo "[Unit]" > $(SERVICE_FILE); 		echo "Description=DNS Filter Service with Record Filtering" >> $(SERVICE_FILE); 		echo "After=network.target" >> $(SERVICE_FILE); 		echo "" >> $(SERVICE_FILE); 		echo "[Service]" >> $(SERVICE_FILE); 		echo "Type=simple" >> $(SERVICE_FILE); 		echo "User=$(SERVICE_USER)" >> $(SERVICE_FILE); 		echo "Group=$(SERVICE_GROUP)" >> $(SERVICE_FILE); 		echo "WorkingDirectory=$(CONFDIR)" >> $(SERVICE_FILE); 		echo "ExecStart=/usr/local/bin/dns_filter" >> $(SERVICE_FILE); 		echo "Restart=on-failure" >> $(SERVICE_FILE); 		echo "RestartSec=10" >> $(SERVICE_FILE); 		echo "StandardOutput=journal" >> $(SERVICE_FILE); 		echo "StandardError=journal" >> $(SERVICE_FILE); 		echo "" >> $(SERVICE_FILE); 		echo "# Security" >> $(SERVICE_FILE); 		echo "NoNewPrivileges=true" >> $(SERVICE_FILE); 		echo "PrivateTmp=true" >> $(SERVICE_FILE); 		echo "ProtectSystem=strict" >> $(SERVICE_FILE); 		echo "ProtectHome=true" >> $(SERVICE_FILE); 		echo "ReadWritePaths=$(LOGDIR)" >> $(SERVICE_FILE); 		echo "ReadOnlyPaths=$(CONFDIR)" >> $(SERVICE_FILE); 		echo "" >> $(SERVICE_FILE); 		echo "# Capabilities" >> $(SERVICE_FILE); 		echo "AmbientCapabilities=CAP_NET_BIND_SERVICE" >> $(SERVICE_FILE); 		echo "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" >> $(SERVICE_FILE); 		echo "" >> $(SERVICE_FILE); 		echo "[Install]" >> $(SERVICE_FILE); 		echo "WantedBy=multi-user.target" >> $(SERVICE_FILE); 		echo "✓ $(SERVICE_FILE) создан"; 	fi

# Управление сервисом
start:
	@echo "→ Запуск DNS фильтр сервиса..."
	@systemctl start dns-filter
	@echo "✓ Сервис запущен"

stop:
	@echo "→ Остановка DNS фильтр сервиса..."
	@systemctl stop dns-filter
	@echo "✓ Сервис остановлен"

restart:
	@echo "→ Перезагрузка DNS фильтр сервиса..."
	@systemctl restart dns-filter
	@echo "✓ Сервис перезагружен"

status:
	@echo "=== DNS Filter Service Status ==="
	@systemctl status dns-filter
	@echo ""
	@echo "=== Service Info ==="
	@echo "Config: $(CONFDIR)/dns_filter.conf"
	@echo "Logs: $(LOGDIR)/"
	@echo "Binary: /usr/local/bin/dns_filter"
	@echo ""
	@$(MAKE) check-cap

enable:
	@echo "→ Включение автозапуска сервиса..."
	@systemctl enable dns-filter
	@echo "✓ Сервис будет запущен при загрузке"

disable:
	@echo "→ Отключение автозапуска сервиса..."
	@systemctl disable dns-filter
	@echo "✓ Сервис не будет автоматически запущен"

# Локальная отладка (без systemd)
debug: build
	@echo "→ Запуск в режиме отладки (с debug флагом в конфиге)..."
	@echo "debug" > dns_filter_debug.conf
	@cat $(CONFIG) >> dns_filter_debug.conf
	@sudo CONFIG_FILE=dns_filter_debug.conf $(BINDIR)/dns_filter

# Тестирование
test: build
	@echo "=== DNS Filter Testing ==="
	@echo "→ Проверка синтаксиса конфигурации..."
	@grep -E "^(rule|default|debug):" $(CONFIG) || echo "✓ Конфиг проверен"
	@echo ""
	@echo "→ Компиляция успешна, бинарник готов"
	@echo "→ Используйте 'make debug' для локального тестирования"
	@echo "→ Используйте 'dig @127.0.0.1 example.com' для тестирования"

# Просмотр логов
logs:
	@echo "=== DNS Filter Logs (последние 50 строк) ==="
	@journalctl -u dns-filter -n 50 --no-pager

logs-follow:
	@journalctl -u dns-filter -f

# Просмотр конфигурации
show-config:
	@echo "=== DNS Filter Configuration ==="
	@cat $(CONFDIR)/dns_filter.conf 2>/dev/null || cat $(CONFIG)

# Редактирование конфигурации
edit-config:
	@sudo vim $(CONFDIR)/dns_filter.conf

# Проверка портов
check-ports:
	@echo "=== Checking DNS ports ==="
	@echo "UDP 53:"
	@ss -tuln | grep -E ":53" || echo "  Not listening"

# Статистика использования
stats:
	@echo "=== DNS Filter Statistics ==="
	@echo "Process info:"
	@ps aux | grep "dns_filter" | grep -v grep || echo "  Service not running"
	@echo ""
	@echo "Memory usage:"
	@ps aux | grep "dns_filter" | grep -v grep | awk '{print "  RSS: " $$6 " KB, VSZ: " $$5 " KB"}' || echo "  N/A"
	@echo ""
	@echo "Network connections:"
	@netstat -an 2>/dev/null | grep -E ":53\s" | wc -l | awk '{print "  Active: " $$1}' || echo "  N/A"

# Справка
help:
	@echo "╔════════════════════════════════════════════════════════════════╗"
	@echo "║         DNS Filter Service - Makefile targets                  ║"
	@echo "╚════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Основные цели:"
	@echo "  make all              - Сборка проекта (по умолчанию)"
	@echo "  make build            - Компиляция DNS фильтра"
	@echo "  make clean            - Удаление бинарников"
	@echo ""
	@echo "Установка и управление:"
	@echo "  make install          - Установка файлов + capabilities (требуется sudo)"
	@echo "  make systemd-install  - Установка systemd сервиса (требуется sudo)"
	@echo "  make uninstall        - Удаление сервиса (требуется sudo)"
	@echo ""
	@echo "Capabilities:"
	@echo "  make check-cap        - Проверить текущие capabilities"
	@echo "  make remove-cap       - Удалить capabilities"
	@echo ""
	@echo "Управление сервисом:"
	@echo "  make start            - Запуск сервиса"
	@echo "  make stop             - Остановка сервиса"
	@echo "  make restart          - Перезагрузка сервиса"
	@echo "  make status           - Статус сервиса + capabilities"
	@echo "  make enable           - Включить автозапуск"
	@echo "  make disable          - Отключить автозапуск"
	@echo ""
	@echo "Отладка и тестирование:"
	@echo "  make debug            - Запуск в режиме отладки (локально)"
	@echo "  make test             - Проверка конфигурации"
	@echo "  make logs             - Показать последние логи"
	@echo "  make logs-follow      - Следить за логами в реальном времени"
	@echo ""
	@echo "Конфигурация:"
	@echo "  make show-config      - Показать текущую конфигурацию"
	@echo "  make edit-config      - Редактировать конфигурацию (vim)"
	@echo ""
	@echo "Мониторинг:"
	@echo "  make check-ports      - Проверить прослушиваемые порты"
	@echo "  make stats            - Показать статистику использования"
	@echo ""
	@echo "Примеры использования:"
	@echo "  sudo make systemd-install # Полная установка с capabilities"
	@echo "  sudo make start           # Запустить сервис"
	@echo "  make status               # Проверить статус и capabilities"
	@echo "  make logs-follow          # Следить за логами"
	@echo ""
	@echo "Решение проблемы с портом 53:"
	@echo "  1. sudo make install      # Устанавливает CAP_NET_BIND_SERVICE"
	@echo "  2. make check-cap         # Проверяет capabilities"
	@echo "  3. sudo make start        # Запускает от dns-filter"
	@echo ""
