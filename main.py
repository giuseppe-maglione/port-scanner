import socket
import threading
from multiprocessing import Queue
import sys

options = [1,2,3]
common_ports = {21:'FTP', 22:'SSH', 25:'SMTP', 53:'DNS', 80:'HTTP', 135:'RPC', 443:'HTTPS', 3306:'MySQL', 3389:'RDP', 8080:'HTTP Alt'}
custom_ports = {}
open_ports = {}
closed_ports = {}
common_tld = ['.com', '.org', '.net', '.edu', '.gov', '.mil', '.int', '.info', '.biz', '.name', '.pro', '.app', '.xyz', '.online', '.store', '.it', 
                '.uk', '.de', '.fr', '.es', '.us', '.cn', '.ru', '.jp', '.au', '.ca', '.br', '.in', '.mx', '.nl', '.ch', '.se', '.no', '.dk', '.fi', 
                '.za', '.gr', '.ar', '.pl', '.eu', '.asia', '.tv', '.me', '.io'
            ]

def worker(host, port, name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(4)
    res = sock.connect_ex((host, port))
    if res == 0:
        open_ports[port] = name
    else:
        closed_ports[port] = name
    sock.close()

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

def print_result(open_ports, closed_ports):
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

if __name__ == '__main__':

    print('-'*50)
    
    print('Port scanner tool')
    print('GitHub: https://github.com/giuseppe-maglione/port-scanner')
    target = input('Enter an IP andress or a domain: ')
    for tld in common_tld:
        if tld in target:
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                print('Unable to resolve hostname: ' + str(target))
                sys.exit(-1)
            else:
                break
    else:
        ip = target

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
    
    print_result(open_ports, closed_ports)
    sys.exit(0)

    
