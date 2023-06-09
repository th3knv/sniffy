from socketserver import UDPServer
import tkinter as tk
import requests
from telnetlib import IP
import threading
from scapy.all import *
import time
import socket
import sys

packet_list = []

try:
    def input_thread(packet_list):
        # Get user input and store it in a global variable
        global review_packet
        while True:
            print("\033[33m||Press 'r' to review IP Addr|| \033[0m\n")
            review_packet = input("\033[33m||Enter package number to review package|| \033[0m\n")
            try:
                packet_index = int(review_packet) - 1
                if packet_index >= 0 and packet_index < len(packet_list):
                    print(packet_list[packet_index].show())
                else:
                    print(f"No packet found: {packet_index + 1}")
            except ValueError:
                print(f"Invalid input: {review_packet}")

            if review_packet == 'r':
                # Function to perform the IP address scan and display the results
                def scan_ip():
        # Get the IP address from the entry widget
                    ip_add = ip_entry.get()
                    url = 'https://ipinfo.io/' + ip_add
                    response = requests.get(url)
                    data = response.json()
        
        # Extract the information about the IP address
                    status = data.get('status', 'Not Found')
                    ip = data.get('ip', 'Not Found')
                    hostname = data.get('hostname', 'Not Found')
                    city = data.get('city', 'Not Found')
                    region = data.get('region', 'Not Found')
                    country = data.get('country', 'Not Found')
                    #latitude, longitude = data.get('loc', 'Not Found').split(',')
                    organization = data.get('org', 'Not Found')
                    postal_code = data.get('postal', 'Not Found')
                    timezone = data.get('timezone', 'Not Found')
                    as_ = data.get('as', 'Not Found')
                    anycast = data.get('anycast', 'Not Found')
                    abuse_email = data.get('email', 'Not Found')
                    abuse_phone = data.get('phone', 'Not Found')

        # Format the results as a string
                    response = f'Response Report: {response.status_code}'
                    results = f'Status: {status}\n'
                    results += f'IP: {ip}\n'
                    results += f'Hostname: {hostname}\n'
                    results += f'City: {city}\n'
                    results += f'Region: {region}\n'
                    results += f'Country: {country}\n'
                    results += f'Company: {organization}\n'
                    #results += f'Coordinates: {latitude}, {longitude}\n'
                    results += f'Postal: {postal_code}\n'
                    results += f'TimeZone: {timezone}\n'
                    results += f'AS: {as_}\n'
                    results += f'AnyCast: {anycast}\n'
                    results += f'Abuse email: {abuse_email}\n'
                    results += f'Abuse phone: {abuse_phone}\n'

        # Update the results text widget with the response and results
                    results_text.delete("1.0", "end")  # Clear the text widget
                    results_text.insert("1.0", response+'\n'+results)  # Insert the new text

    # Create the main window
                root = tk.Tk()
                root.geometry('350x480+300+50')
                root.title("IP Scanner")

    # Create a label and text entry widget for the IP address
                ip_label = tk.Label(root, text="IP Address Review", font=('Arial', 16))
                hint_label = tk.Label(root, text='Invalid Address = No results / Error', font=('Arial', 9), fg='red')
                hint2_label = tk.Label(root, text='Debug method: Adjust window for better info view', font=('Arial', 8), fg='green')
                ip_label.pack()
                hint_label.pack()
                hint2_label.pack()
                ip_entry = tk.Entry(root, font = ('Arial', 16))
                ip_entry.pack()

    # Create a button to start the IP scan
                scan_button = tk.Button(root, text="Scan", font = ('', 10), command=scan_ip)
                scan_button.pack()

    # Create a scrollbar and a text widget to display the results
                scrollbar = tk.Scrollbar(root)
                scrollbar.pack(side="right", fill="y")
                results_text = tk.Text(root, font=('Arial', 14), yscrollcommand=scrollbar.set)
                results_text.pack()
                scrollbar.config(command=results_text.yview)

    # Run the main loop
                root.mainloop()

    input_thread = threading.Thread(target=input_thread, args=(packet_list,))
    input_thread.start()


    def packet_callback(packet):
        # Check if the packet contains an IP layer
        if IP in packet:
            try:
                sourcedomain_name = socket.gethostbyaddr(packet[IP].src)[0]
                destdomain_name = socket.gethostbyaddr(packet[IP].dst)[0]
            except socket.herror:
                sourcedomain_name ='Unknown'
                destdomain_name = 'Unknown'






            # Print the packet's source and destination IP addresses, domain names, and protocol
            count = len(packet_list) + 1
            packet_list.append(packet)
            print(f"\033[34mSource:\033[0m {packet[IP].src}: (\033[33m{sourcedomain_name}\033[0m) \033[34mDestination:\033[0m {packet[IP].dst}: (\033[33m{destdomain_name}\033[0m)  {count}")
            # Print the hex dump of the packet
            #print(packet.show())
        else:
            pass

    # Start sniffing traffic on the wlan0 interface, with promiscuous mode enabled
    sniff(iface="wlan0", prn=packet_callback, promisc=True)

except KeyboardInterrupt:
    print('Bye!')
    sys.exit()
