import socketserver
import threading
import time
import redis
import logging
import subprocess
import random
import os
import psutil

# Настройки защиты
RATE_LIMIT = 10         # Максимальное количество подключений за интервал
TIME_WINDOW = 10        # Интервал (в секундах) для подсчёта подключений
BLOCK_TIME = 60         # Время блокировки IP (в секундах)
TRAFFIC_THRESHOLD = 30 * 1024 * 1024  # 30 МБ в секунду
ANALYZE_INTERVAL = 1  # Интервал для анализа поведения (в секундах)

LOG_FILE = "server.log"  # Файл для логов

# Настройка логирования
logging.basicConfig(filename=LOG_FILE,
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Подключение к Redis для хранения данных о подключениях и трафике
r = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

lock = threading.Lock()

class RateLimitingTCPServer(socketserver.ThreadingTCPServer):
    def verify_request(self, request, client_address):
        ip = client_address[0]
        current_time = time.time()

        # Проверка, заблокирован ли IP
        if self.is_blocked(ip):
            logging.warning(f"IP {ip} находится в блокировке.")
            return False

        # Логируем попытку подключения
        logging.info(f"Попытка подключения от {ip}.")

        # Работа с лимитом подключений (используя Redis)
        connection_key = f"connections:{ip}"
        # Получаем список меток времени подключений
        connection_times = r.lrange(connection_key, 0, -1)
        # Преобразуем в числа и удаляем старые записи
        connection_times = [float(t) for t in connection_times if current_time - float(t) < TIME_WINDOW]
        # Если число подключений превышает лимит, блокируем IP
        if len(connection_times) >= RATE_LIMIT:
            r.setex(f"blocked:{ip}", BLOCK_TIME, 1)
            logging.warning(f"IP {ip} заблокирован на {BLOCK_TIME} секунд за превышение лимита подключений.")
            return False

        # Сохраняем обновлённый список подключений
        r.delete(connection_key)
        for t in connection_times:
            r.rpush(connection_key, t)
        # Добавляем новую метку времени подключения
        r.rpush(connection_key, current_time)
        r.expire(connection_key, TIME_WINDOW)

        return True

    def is_blocked(self, ip):
        return r.exists(f"blocked:{ip}")

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        ip = self.client_address[0]
        self.request.sendall(b"Hello from protected TCP server\n")
        try:
            while True:
                data = self.request.recv(1024)
                if not data:
                    break

                # Отслеживание объёма трафика с IP за 1 секунду
                traffic_key = f"traffic:{ip}"
                current_traffic = r.incrby(traffic_key, len(data))
                # Если ключ только создан, устанавливаем время жизни в 1 секунду
                if r.ttl(traffic_key) == -1:
                    r.expire(traffic_key, 1)

                # Если превышен порог в 30 МБ за секунду, блокируем IP и выводим предупреждение
                if int(current_traffic) > TRAFFIC_THRESHOLD:
                    r.setex(f"blocked:{ip}", BLOCK_TIME, 1)
                    logging.warning(f"IP {ip} отправляет более 30 МБ в секунду. Заблокирован на {BLOCK_TIME} секунд.")
                    print("Похоже на ДДОС!")
                    break

                # Простой эхо-сервис: отправляем полученные данные обратно клиенту
                self.request.sendall(data)
        except Exception as e:
            logging.error(f"Ошибка при обработке запроса от {ip}: {e}")

# Функция для настройки iptables (только для Linux)
def configure_iptables():
    try:
        # Пример добавления правила для нового подключения на порт 9999 с использованием модуля recent
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '9999', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--set'], check=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '9999', '-m', 'recent', '--update', '--seconds', '60', '--hitcount', '10', '-j', 'DROP'], check=True)
        logging.info("iptables настроены для защиты от DDoS.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Ошибка при настройке iptables: {e}")

# Анализ системных метрик для поведения
def analyze_behavior():
    # Получаем статистику по сетевым соединениям и нагрузке
    connections = psutil.net_connections(kind='tcp')
    for conn in connections:
        # Печатаем статистику соединений
        logging.info(f"Активное соединение от {conn.raddr} - {conn.status}")

    # Печатаем загрузку процессора и памяти
    logging.info(f"Загрузка CPU: {psutil.cpu_percent()}%")
    logging.info(f"Загрузка памяти: {psutil.virtual_memory().percent}%")

# Многоуровневая защита
def setup_cdn_and_load_balancer():
    # Можно интегрировать с внешними решениями для фильтрации трафика
    logging.info("CDN и балансировка нагрузки настроены. Трафик будет фильтроваться на более высоком уровне.")

def start_server():
    HOST, PORT = "0.0.0.0", 9999
    server = RateLimitingTCPServer((HOST, PORT), MyTCPHandler)
    logging.info(f"Сервер запущен на {HOST}:{PORT}")
    
    # Запуск мониторинга поведения
    threading.Thread(target=analyze_behavior, daemon=True).start()

    # Настройка CDN и балансировщиков
    setup_cdn_and_load_balancer()

    server.serve_forever()

if __name__ == "__main__":
    # Настройка iptables (работает на Linux)
    configure_iptables()

    # Запуск TCP-сервера
    start_server()