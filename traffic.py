import os
from scapy.all import sniff, IP, TCP, UDP, ARP, Raw  # Импортируем необходимые модули из библиотеки Scapy
# Создаем папку для логов (если её нет)
log_dir = "logs"  # Название директории для хранения логов
os.makedirs(log_dir, exist_ok=True)  # Создаем папку, если она не существует
# Функция для записи данных в файл
def write_to_file(filename, data):
    """
    Функция записывает строку данных в указанный файл в папке логов.
    :param filename: имя файла, в который записываются данные
    :param data: строка данных, которая будет записана
    """
    filepath = os.path.join(log_dir, filename)  # Формируем путь к файлу
    with open(filepath, "a") as f:  # Открываем файл в режиме добавления (append)
        f.write(data + "\n")  # Записываем строку и добавляем перевод строки
    print(f"Записано в файл: {filepath}")  # Выводим в консоль путь к файлу, куда записаны данные
# Функция определения типа шифрования
def detect_encryption(pkt):
    """
    Анализирует, является ли пакет зашифрованным (SSL/TLS) или нет.
    Определяет версии TLS по заголовку Handshake.
    :param pkt: пакет, который анализируется
    :return: строка с информацией о шифровании
    """
    if pkt.haslayer(TCP) and pkt[TCP].dport in [443, 993, 995, 465]:  # Проверяем, используется ли один из стандартных портов SSL/TLS
        if pkt.haslayer(Raw):  # Если есть полезная нагрузка (может содержать TLS Handshake)
            payload = bytes(pkt[Raw])  # Преобразуем данные в байтовый формат
            if payload.startswith(b"\x16\x03\x01"):  # Проверяем заголовок для TLS 1.0
                return "TLS 1.0"
            elif payload.startswith(b"\x16\x03\x02"):  # Заголовок для TLS 1.1
                return "TLS 1.1"
            elif payload.startswith(b"\x16\x03\x03"):  # Заголовок для TLS 1.2
                return "TLS 1.2"
            elif payload.startswith(b"\x16\x03\x04"):  # Заголовок для TLS 1.3
                return "TLS 1.3"
        return "Зашифрованный трафик (SSL/TLS)"  # Если порт относится к SSL/TLS, но точная версия не определена
    return "Нет шифрования"  # Если пакет не относится к зашифрованному трафику
# Функция обработки сетевых пакетов
def packet_handler(pkt):
    """
    Обрабатывает перехваченные сетевые пакеты и записывает их в соответствующие файлы логов.
    :param pkt: перехваченный пакет
    """
    if pkt.haslayer(IP):  # Проверяем, является ли пакет IP-пакетом
        src_ip = pkt[IP].src  # Получаем IP-адрес источника
        dst_ip = pkt[IP].dst  # Получаем IP-адрес назначения
        protocol = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "Other"  # Определяем тип протокола (TCP, UDP или другой)
        encryption = detect_encryption(pkt)  # Проверяем, используется ли шифрование
        log_entry = f"IP {src_ip} → {dst_ip} | Протокол: {protocol} | Шифрование: {encryption}"  # Формируем строку для логирования
        if pkt.haslayer(TCP):  # Если это TCP-пакет
            write_to_file("tcp.log", log_entry)  # Записываем в лог TCP-трафика
            if "TLS" in encryption or "SSL" in encryption:  # Если обнаружено шифрование TLS/SSL
                write_to_file("tls.log", log_entry)  # Записываем в лог зашифрованного трафика
        elif pkt.haslayer(UDP):  # Если это UDP-пакет
            write_to_file("udp.log", log_entry)  # Записываем в лог UDP-трафика
        print(log_entry)  # Выводим информацию о пакете в консоль
    elif pkt.haslayer(ARP):  # Если это ARP-запрос
        log_entry = f"ARP Запрос: {pkt.summary()}"  # Формируем строку для логирования
        write_to_file("arp.log", log_entry)  # Записываем в лог ARP-запросов
        print(log_entry)  # Выводим в консоль информацию о ARP-запросе
# Запуск анализа трафика в реальном времени
print("Анализ трафика... (нажмите Ctrl+C для остановки)")  # Выводим сообщение о начале мониторинга сети
sniff(prn=packet_handler, store=False)  # Запускаем перехват пакетов, передавая их в функцию packet_handler
