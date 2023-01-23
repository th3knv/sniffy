import tkinter as tk
import requests
from telnetlib import IP
import threading
from scapy.all import *
import time

def input_thread():
    # Get user input and store it in a global variable
    global review_
    while True:
        review_ = input("\033[33mPress 'r' to review \033[0m")
        if review_ == 'r':
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

input_thread = threading.Thread(target=input_thread)
input_thread.start()

# The rest of the program's code can run concurrently with the input prompt
while True:
    # Define a callback function that will be called for each packet
    def packet_callback(packet):
        # Check if the packet contains an IP layer
        if IP in packet:
            # Print the packet's source and destination IP addresses
            print(f"\033[34mSource:\033[0m {packet[IP].src} \033[34mDestination:\033[0m {packet[IP].dst}")
            time.sleep(0.5)
        else:
            # Print a message indicating that the packet does not contain an IP layer
            print("\033[31mPacket does not contain an IP layer\033[31m")
    sniff(prn=packet_callback)
