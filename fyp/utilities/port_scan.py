from datetime import datetime
from queue import Queue
from time import sleep
import nmap
import re  		    # To ensure that the input is correctly formatted.
from threading import Thread
import threading
import socket

port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
nm = nmap.PortScanner()
thread_list = [] 
print_lock = threading.Lock() 
scan_data_list = [] 

class bcolors:
    PURPLE = '\033[1;95m'
    OKBLUE = '\033[1;94m'
    GREEN = '\033[1;92m'
    ORANGE = '\033[1;93m'
    RED = '\033[1;91m'
    CYAN = "\033[1;96m"
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT  = '\033[41m' # For critical errors and crashes
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT  = '\033[43m'
    BG_LOW_TXT  = '\033[44m'
    BG_INFO_TXT = '\033[42m'

    BG_SCAN_TXT_START = '\x1b[6;30;42m'
    BG_SCAN_TXT_END   = '\x1b[0m'

scan_data_list = []
scan_data_list.clear()
def nmapScan(target,port):
    result = nm.scan(target, str(port))
    
    for host in nm.all_hosts():						# nm.all_hosts() = ['10.10.10.10']
        for proto in nm[host].all_protocols():      # nm[host].all_protocols() = tcp
            pass

    service = (result['scan'][host][proto][port]['name'])
    service_product = (result['scan'][host][proto][port]['product'])
    service_version = (result['scan'][host][proto][port]['version'])
    service_os = (result['scan'][host][proto][port]['extrainfo'])
    print(f"{bcolors.GREEN}[*]{bcolors.RESET} Port {port}/{proto}: {bcolors.GREEN}open{bcolors.RESET}" + f"\tService: {bcolors.GREEN}{service}{bcolors.RESET}" + f"\tVersion: {bcolors.GREEN}{service_product} {service_version}{bcolors.RESET}" + f"\tOS: {bcolors.GREEN}{service_os} {bcolors.RESET}")
    scan_data_list.append({'port': port, 'protocol': proto, 'service': service, 'version': service_product+service_version, 'os_family': service_os})

    sleep(0.1)

def portScan(target,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection = s.connect((target, port))
        with print_lock:
            nmapScan(port)
        connection.close()
    except:
        pass

def port_scan_start(target,port_range):
    port_range_fixer = port_range_pattern.search(port_range.replace(" ",""))

    if port_range_fixer:
        port_min = int(port_range_fixer.group(1))
        port_max = int(port_range_fixer.group(2))

    start_time = datetime.now()
    print(f"\nStarting {bcolors.CYAN}Full Scan{bcolors.RESET} for {bcolors.ORANGE}{target}{bcolors.RESET} at {bcolors.ORANGE}{start_time}{bcolors.RESET}")

    threads = []
    for ip in range(port_min, port_max + 1):
        thread = Thread(target=portScan, args=(target,ip,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()
    end_time = datetime.now()
    print(f"Ending {bcolors.CYAN}Full Scan{bcolors.RESET} for {bcolors.ORANGE}{target}{bcolors.RESET} at {bcolors.ORANGE}{end_time}{bcolors.RESET}")
    total_time = end_time - start_time
    print(f"\nTotal Time Elasped: {bcolors.CYAN}{total_time}{bcolors.RESET}")
    return scan_data_list