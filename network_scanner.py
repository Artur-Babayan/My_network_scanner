# Импортируем необходимые библиотеки
import argparse  # Библиотека для работы с аргументами командной строки
import nmap  # Библиотека для сканирования сети
from scapy.all import ARP, Ether, srp  # Библиотеки для создания ARP-запросов и обработки сетевых пакетов
import socket  # Библиотека для работы с сетевыми функциями
import netifaces as ni  # Библиотека для доступа к информации о сетевых интерфейсах

# Класс для сканирования сети с использованием ARP-запросов
class ARPScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip  # Целевой IP-адрес или подсеть
        self.clients = []  # Список найденных устройств

    def scan(self):
        arp = ARP(pdst=self.target_ip)  # Создаем ARP-запрос с указанным целевым IP-адресом
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Создаем Ethernet-кадр с широковещательным адресом
        packet = ether/arp  # Складываем Ethernet-кадр и ARP-запрос в один пакет

        result = srp(packet, timeout=1, verbose=False)[0]  # Отправляем пакет и получаем ответы

        for sent, received in result:
            ip = received.psrc  # Извлекаем IP-адрес ответившего устройства
            mac = received.hwsrc  # Извлекаем MAC-адрес ответившего устройства

            try:
                _, _, hostnames = socket.gethostbyaddr(ip)  # Попытка получить имя устройства по IP-адресу
                hostname = hostnames[0]  # Извлекаем первое имя из списка
            except (socket.herror, IndexError):
                hostname = "N/A"  # Если имя не найдено, используем "N/A"

            self.clients.append({'ip': ip, 'mac': mac, 'hostname': hostname})  # Добавляем информацию об устройстве в список

        return self.clients

# Класс для сканирования сети с использованием Nmap
class NmapScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip  # Целевой IP-адрес или подсеть
        self.scanner = nmap.PortScanner()  # Инициализируем сканер Nmap

    def scan(self):
        self.scanner.scan(hosts=self.target_ip, arguments='-sn')  # Выполняем сканирование Nmap для обнаружения активных устройств

    def get_active_device_info(self):
        active_device_info = []
        for host in self.scanner.all_hosts():
            if self.scanner[host].state() == 'up':  # Проверяем, активно ли устройство
                hostname = self.scanner[host].get('hostnames', 'N/A')  # Получаем имя устройства
                active_device_info.append({'ip': host, 'hostname': hostname})  # Добавляем информацию об активном устройстве в список
        return active_device_info

# Функция для получения IP-адреса сетевого интерфейса
def get_interface_ip(interface):
    try:
        local_ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']  # Получаем IP-адрес для указанного интерфейса
        return local_ip
    except (ValueError, KeyError):
        return None  # В случае ошибки возвращаем None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Сканирование и получение информации об устройствах в локальной сети.")
    parser.add_argument("interface", metavar="ИНТЕРФЕЙС", type=str, help="Имя сетевого интерфейса (например, eno1)")
    args = parser.parse_args()

    interface_name = args.interface  # Получаем имя сетевого интерфейса из аргументов командной строки

    # Получаем IP-адрес, ассоциированный с указанным сетевым интерфейсом
    local_ip = get_interface_ip(interface_name)

    if local_ip is None:
        print(f"Не удалось определить IP-адрес для сетевого интерфейса {interface_name}.")
        exit()

    # Создаем целевой IP-адрес на основе подсети локальной сети
    target_ip = local_ip + "/24"

    arp_scanner = ARPScanner(target_ip)  # Создаем объект ARP-сканера
    nmap_scanner = NmapScanner(target_ip)  # Создаем объект Nmap-сканера

    try:
        arp_clients = arp_scanner.scan()  # Выполняем ARP-сканирование и получаем список устройств
        print("Доступные устройства, обнаруженные с помощью ARP-сканирования:")
        print("IP" + " " * 18 + "MAC" + " " * 20 + "Hostname")
        for client in arp_clients:
            print("{:16}    {}    {}".format(client['ip'], client['mac'], client['hostname']))

        nmap_scanner.scan()  # Выполняем сканирование Nmap
        active_nmap_devices = nmap_scanner.get_active_device_info()  # Получаем информацию об активных устройствах
        print("\nАктивные устройства, обнаруженные с помощью сканирования Nmap:")
        print("IP" + " " * 18 + "Hostname")
        for device in active_nmap_devices:
            print("{:16}    {}".format(device['ip'], device['hostname']))

    except Exception as e:
        print(f"Произошла ошибка: {str(e)}")

