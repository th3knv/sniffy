from socketserver import UDPServer
import requests
from scapy.layers.inet import IP
import threading
from scapy.all import *
import time
import socket
import sys

packet_list = []

#get local ip

def get_local_ip():
    try:
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_socket.connect(('8.8.8.8', 80))  
        local_ip = temp_socket.getsockname()[0]  
        temp_socket.close()  
        return local_ip
    except socket.error:
        return None
local_ip = get_local_ip()

try:
    def input_thread(packet_list):
        global review_packet
        while True:
            review_packet = input("\033[33m||Enter packet number to review IP & packet|| \033[0m\n")
            try:
                packet_index = int(review_packet) - 1
                if packet_index >= 0 and packet_index < len(packet_list):
                    packet = packet_list[packet_index]

                    url = 'https://ipinfo.io/' + packet[IP].dst
                    response = requests.get(url)
                    data = response.json()

                    status = data.get('status', '\033[31mNot Found\033[0m')
                    ip = data.get('ip', '\033[31mNot Found\033[0m')
                    hostname = data.get('hostname', '\033[31mNot Found\033[0m')
                    city = data.get('city', '\033[31mNot Found\033[0m')
                    region = data.get('region', '\033[31mNot Found\033[0m')
                    country = data.get('country', '\033[31mNot Found\033[0m')
                    organization = data.get('org', '\033[31mNot Found\033[0m')
                    postal_code = data.get('postal', '\033[31mNot Found\033[0m')
                    timezone = data.get('timezone', '\033[31mNot Found\033[0m')
                    as_ = data.get('as', '\033[31mNot Found\033[0m')
                    anycast = data.get('anycast', '\033[31mNot Found\033[0m')
                    abuse_email = data.get('email', '\033[31mNot Found\033[0m')
                    abuse_phone = data.get('phone', '\033[31mNot Found\033[0m')
                    #print results
                    response_report = f'\033[32mResponse Report:\033[0m {response.status_code}'
                    results = f'\033[32mStatus:\033[0m {status}\n'
                    results += f'\033[32mIP:\033[0m {ip}\n'
                    results += f'\033[32mHostname:\033[0m {hostname}\n'
                    results += f'\033[32mCity:\033[0m {city}\n'
                    results += f'\033[32mRegion:\033[0m {region}\n'
                    results += f'\033[32mCountry:\033[0m {country}\n'
                    results += f'\033[32mCompany:\033[0m {organization}\n'
                    results += f'\033[32mPostal:\033[0m {postal_code}\n'
                    results += f'\033[32mTimeZone:\033[0m {timezone}\n'
                    results += f'\033[32mAS:\033[0m {as_}\n'
                    results += f'\033[32mAnyCast:\033[0m {anycast}\n'
                    results += f'\033[32mAbuse email:\033[0m {abuse_email}\n'
                    results += f'\033[32mAbuse phone:\033[0m {abuse_phone}\n'
                       
                    print('')
                    print(response_report)
                    print(results)
                    print(packet.show())
                else:
                    print(f"No packet found: {packet_index + 1}")
            except ValueError:
                print(f"Invalid input: {review_packet}")

    input_thread = threading.Thread(target=input_thread, args=(packet_list,))
    input_thread.start()

    def packet_callback(packet):
        if IP in packet:
            if packet[IP].src == local_ip and packet[IP].dst == "192.168.1.1":
                return  # Filter package, it prints it a lot
            if packet[IP].src == "192.168.1.1" and packet[IP].dst == local_ip:
                return  # Filter package, it prints it a lot

            try:
                sourcedomain_name = socket.gethostbyaddr(packet[IP].src)[0]
                destdomain_name = socket.gethostbyaddr(packet[IP].dst)[0]
            except socket.herror:
                sourcedomain_name = 'Unknown'
                destdomain_name = 'Unknown'

            count = len(packet_list) + 1
            packet_list.append(packet)
            time.sleep(0.5)
            print(f"\033[34mSource:\033[0m {packet[IP].src}: (\033[33m{sourcedomain_name}\033[0m) \033[34mDestination:\033[0m {packet[IP].dst}: (\033[33m{destdomain_name}\033[0m)  {count}")
        else:
            pass

    sniff(iface="wlan0", prn=packet_callback, promisc=True)

except KeyboardInterrupt:
    print('Bye!')
    sys.exit()
