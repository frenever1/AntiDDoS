import asyncio
import aioredis
import logging
import subprocess
import random
import os
import psutil
from concurrent.futures import ThreadPoolExecutor
from aiohttp import web

# Настройки защиты
RATE_LIMIT = 10         # Максимальное количество подключений за интервал
TIME_WINDOW = 10        # Интервал (в секундах) для подсчёта подключений
BLOCK_TIME = 60         # Время блокировки IP (в секундах)
TRAFFIC_THRESHOLD = 30 * 1024 * 1024  # 30 МБ в секунду
ANALYZE_INTERVAL = 10  # Интервал для анализа поведения (в секундах)
LOG_FILE = "server.log"  # Файл для логов

# Настройка логирования
logging.basicConfig(filename=LOG_FILE,
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Redis-подключение
redis = None

async def setup_redis():
    global redis
    redis = await aioredis.create_redis_pool('redis://localhost')

# Проверка и блокировка IP
async def is_blocked(ip):
    return await redis.exists(f"blocked:{ip}")

async def block_ip(ip):
    await redis.setex(f"blocked:{ip}", BLOCK_TIME, 1)
    logging.warning(f"IP {ip} заблокирован на {BLOCK_TIME} секунд за превышение лимита подключений.")

# Ограничение подключений
async def rate_limit(ip):
    current_time = int(time.time())
    connection_key = f"connections:{ip}"
    
    # Очистка старых подключений
    await redis.zremrangebyscore(connection_key, '-inf', current_time - TIME_WINDOW)
    connection_times = await redis.zcard(connection_key)
    
    if connection_times >= RATE_LIMIT:
        await block_ip(ip)
        return False
    else:
        await redis.zadd(connection_key, current_time, current_time)
        await redis.expire(connection_key, TIME_WINDOW)
        return True

# Проверка и блокировка по трафику
async def check_traffic(ip, data_len):
    traffic_key = f"traffic:{ip}"
    current_traffic = await redis.incrby(traffic_key, data_len)
    
    if await redis.ttl(traffic_key) == -1:
        await redis.expire(traffic_key, 1)
    
    if current_traffic > TRAFFIC_THRESHOLD:
        await block_ip(ip)
        return False
    return True

# Анализ системных метрик
async def analyze_behavior():
    while True:
        connections = psutil.net_connections(kind='tcp')
        for conn in connections:
            logging.info(f"Активное соединение от {conn.raddr} - {conn.status}")
        logging.info(f"Загрузка CPU: {psutil.cpu_percent()}%")
        logging.info(f"Загрузка памяти: {psutil.virtual_memory().percent}%")
        await asyncio.sleep(ANALYZE_INTERVAL)

# Настройка iptables
def configure_iptables():
    try:
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '9999', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--set'], check=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '9999', '-m', 'recent', '--update', '--seconds', '60', '--hitcount', '10', '-j', 'DROP'], check=True)
        logging.info("iptables настроены для защиты от DDoS.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Ошибка при настройке iptables: {e}")

# Эхо-сервер
async def handle_client(reader, writer):
    ip = writer.get_extra_info('peername')[0]
    
    if await is_blocked(ip):
        writer.close()
        await writer.wait_closed()
        return
    
    if not await rate_limit(ip):
        writer.close()
        await writer.wait_closed()
        return

    writer.write(b"Hello from protected TCP server\n")
    await writer.drain()

    try:
        while True:
            data = await reader.read(1024)
            if not data:
                break

            if not await check_traffic(ip, len(data)):
                logging.warning(f"Похоже на ДДОС от IP {ip}!")
                break

            writer.write(data)
            await writer.drain()
    except Exception as e:
        logging.error(f"Ошибка при обработке запроса от {ip}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

# Запуск сервера
async def start_server():
    await setup_redis()
    server = await asyncio.start_server(handle_client, "0.0.0.0", 9999)
    addr = server.sockets[0].getsockname()
    logging.info(f"Сервер запущен на {addr}")
    
    asyncio.create_task(analyze_behavior())
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    configure_iptables()  # Настраиваем iptables для защиты
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        logging.info("Сервер остановлен.")