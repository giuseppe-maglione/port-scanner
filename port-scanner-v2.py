import threading
import sys
import os
from scapy.all import *

options = [1,2,3]
common_ports = {21:'FTP', 22:'SSH', 25:'SMTP', 53:'DNS', 80:'HTTP', 135:'RPC', 443:'HTTPS', 3306:'MySQL', 3389:'RDP', 8080:'HTTP Alt'}
custom_ports = {}
open_ports = {}
closed_ports = {}
other_ports = {}
common_tld = ['.com', '.org', '.net', '.edu', '.gov', '.mil', '.int', '.info', '.biz', '.name', '.pro', '.app', '.xyz', '.online', '.store', '.it', 
                '.uk', '.de', '.fr', '.es', '.us', '.cn', '.ru', '.jp', '.au', '.ca', '.br', '.in', '.mx', '.nl', '.ch', '.se', '.no', '.dk', '.fi', 
                '.za', '.gr', '.ar', '.pl', '.eu', '.asia', '.tv', '.me', '.io'
            ]

def print_ascii_art():
    print("""
$$$$$$$\                    $$\     $$$$$$\                                                       
$$  __$$\                   $$ |   $$  __$$\                                                      
$$ |  $$ |$$$$$$\  $$$$$$\$$$$$$\  $$ /  \__|$$$$$$$\$$$$$$\ $$$$$$$\ $$$$$$$\  $$$$$$\  $$$$$$\  
$$$$$$$  $$  __$$\$$  __$$\_$$  _| \$$$$$$\ $$  _____\____$$\$$  __$$\$$  __$$\$$  __$$\$$  __$$\ 
$$  ____/$$ /  $$ $$ |  \__|$$ |    \____$$\$$ /     $$$$$$$ $$ |  $$ $$ |  $$ $$$$$$$$ $$ |  \__|
$$ |     $$ |  $$ $$ |      $$ |$$\$$\   $$ $$ |    $$  __$$ $$ |  $$ $$ |  $$ $$   ____$$ |      
$$ |     \$$$$$$  $$ |      \$$$$  \$$$$$$  \$$$$$$$\$$$$$$$ $$ |  $$ $$ |  $$ \$$$$$$$\$$ |      
\__|      \______/\__|       \____/ \______/ \_______\_______\__|  \__\__|  \__|\_______\__|      
                                                                                                   
    """)

def worker(host, port, name):
    pkt = IP(dst=host)/TCP(dport=port, flags='S')
    res = sr1(pkt, timeout=4, verbose=False)
    if res:
        if res.haslayer(TCP):
            if res[TCP].flags == 'SA':
                open_ports[port] = name
            elif res[TCP].flags == 'RA':
                closed_ports[port] = name
    else:
        other_ports[port] = name

def get_ip(target):
    for tld in common_tld:
        if tld in target:
            dns_req = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=target))
            dns_res = sr1(dns_req, timeout=2, verbose=False)
            if dns_res and dns_res.haslayer(DNS) and dns_res[DNS].ancount > 0:
                ip = dns_res[DNS].an.rdata
            else:
                print('Unable to resolve hostname: ' + str(target))
                sys.exit(1)
        else:
            ip = target    
    return ip

def get_ports(input):
    for item in input.split(','):
        try:
            port = int(item.strip())
            if port in common_ports.keys():
                custom_ports[port] = common_ports[port]
            else:
                custom_ports[port] = ''
        except ValueError:
            print('Invalid port number for: ' + str(port))
    return custom_ports

def print_result(open_ports, closed_ports, other_ports):
    print('Scanning complete, results: ')
    for port, name in open_ports.items():
        if name == '':
            print(str(port) + ' -> Open')
        else:
            print(name + ' : ' + str(port) + ' -> Open')
    for port, name in closed_ports.items():
        if name == '':
            print(str(port) + ' -> Closed')
        else:
            print(name + ' : ' + str(port) + ' -> Closed')
    
    for port, name in other_ports.items():
        if name == '':
            print(str(port) + ' -> Firewalled or unreachable')
        else:
            print(name + ' : ' + str(port) + ' -> Firewalled or unreachable')
        
def is_root():
    try:
        return os.getuid() == 0
    except Exception as e:
        return False

if __name__ == '__main__':

    print('-'*50)
    print_ascii_art()

    if not is_root():
        print('Warning: Root privileges are needed for this tool, please re-execute as root.')
        print('Read Scapy Documentation for more info.')
        sys.exit(1)

    print('Port scanning tool (Scapy version)')
    print('GitHub: https://github.com/giuseppe-maglione/port-scanner')
    target = input('Enter an IP andress or a domain: ')
    ip = get_ip(target)

    print('Available scan types...')
    print('[+] 1. Common port scanning.')
    print('[+] 2. Custom port scanning.')
    print('[+] 3. All port scanning (1-65535).')

    type = None
    while(type not in options):
        type = int(input('Select any option: '))
        if (type not in options):
            print('Option not available, please retry.')

    threads = []

    if type == options[0]:
        for port, name in common_ports.items():
            th = threading.Thread(target=worker, args=(ip, port, name))
            threads.append(th)
            th.start()

    elif type == options[1]:
        ports = input('Insert ports separated by ",": ')
        custom_ports = get_ports(ports)
        for port, name in custom_ports.items():
            th = threading.Thread(target=worker, args=(ip, port, name))
            threads.append(th)
            th.start()

    elif type == options[2]:
        for port in range(1, 65535):
            th = threading.Thread(target=worker, args=(ip, port, ''))
            threads.append(th)
            th.start()

    else:
        print('Option not available.')
    
    for thread in threads:
        thread.join(timeout=4)

    print('-'*50)    
    
    print_result(open_ports, closed_ports, other_ports)
    print('-'*50)
    sys.exit(0)

    
