Установка всех нужных библиотек используйте команду в cmd 

pip install aioredis aiohttp psutil

--------------------------------------------------

Конфигурация сервера:

Порт по умолчанию: 9999.

Настройки ограничений можно изменить в коде, изменив параметры:

RATE_LIMIT — максимальное количество подключений.

TIME_WINDOW — временной интервал для подсчета подключений.

BLOCK_TIME — время блокировки IP.

TRAFFIC_THRESHOLD — лимит трафика в байтах.

--------------------------------------------------

После запуска сервера можно подключиться к нему через команду в терминале:

telnet localhost 9999

Сервер ответит строкой:

Hello from protected TCP server

Логи:

Все события (подключения, блокировки, ошибки) записываются в файл server.log. Вы можете проверить этот файл для мониторинга активности и выявления потенциальных атак.

Остановка сервера:

Для остановки сервера нажмите Ctrl + C в терминале, где он запущен.
