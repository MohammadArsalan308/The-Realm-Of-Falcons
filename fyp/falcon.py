#!/usr/bin/env python3

import pyfiglet as pyfig 
from datetime import datetime
from queue import Queue
from time import sleep
import nmap
import re  		    # To ensure that the input is correctly formatted.
import os           # To check for internet connectivity.
import threading
import socket
import requests


# Regular Expression Pattern to extract the number of ports you want to scan. 
# You have to specify <lowest_port_number>-<highest_port_number> (ex 10-100)
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
queue = Queue()
# A print_lock is what is used to prevent "double" modification of shared variables.
# This is used so while one thread is using a variable, others cannot access it.
# Once done, the thread releases the print_lock to be used it again.
print_lock = threading.Lock() 
nm = nmap.PortScanner()
thread_list = [] 
subdomains = [] 


# Initializing the color module class
class bcolors:
    PURPLE = '\033[1;95m'
    OKBLUE = '\033[1;94m'
    RED = '\033[1;91m'
    GREEN = '\033[1;92m'
    ORANGE = '\033[1;93m'
    CYAN = "\033[1;96m"
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    OKPURPLE = '\033[95m'

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

  
def nmapScan(port):
    result = nm.scan(target, str(port))
    # The result is quite interesting to look at. Inspect the dictionary it returns. 
    # It contains what was sent to the command line in addition to the port status we're after. 
    # In nmap for port 80 and ip 10.0.0.2 you'd run: nmap -oX - -p 80 -sV 10.0.0.2
    #! print(result)

    for host in nm.all_hosts():						# nm.all_hosts() = ['10.10.10.10']
        for proto in nm[host].all_protocols():      # nm[host].all_protocols() = tcp
            pass

    # We extract the service information from the returned object
    service = (result['scan'][host][proto][port]['name'])
    service_product = (result['scan'][host][proto][port]['product'])
    service_version = (result['scan'][host][proto][port]['version'])
    service_os = (result['scan'][host][proto][port]['extrainfo'])
    print(f"{bcolors.GREEN}[*]{bcolors.RESET} Port {port}/{proto}: {bcolors.GREEN}open{bcolors.RESET}" + f"\tService: {bcolors.GREEN}{service}{bcolors.RESET}" + f"\tVersion: {bcolors.GREEN}{service_product} {service_version}{bcolors.RESET}" + f"\tOS: {bcolors.GREEN}{service_os} {bcolors.RESET}")
    sleep(0.1)

def portScan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection = s.connect((target, port))
        with print_lock:
            nmapScan(port)
        connection.close()
    except:
        pass

# The threader thread pulls a worker from the queue and processes it
def threader():
    while True:
        # Gets a worker from the queue
        worker = queue.get()

        # Run the example job with any available worker in queue (thread)
        portScan(worker)

        # Completed with the job
        queue.task_done()

def perform_threading():
    # How many threads are we going to allow for
    for threads in range(60):
        thread = threading.Thread(target=threader)

        # Classifying as a daemon, so they will die when the main dies
        thread.daemon = True

        # Begins, must come after daemon definition
        thread.start()

# This function sends a GET request to the specified URL and prints the response
def get_request(url):
  # Send the GET request to the specified URL
  response = requests.get(url)

  # Print the response code for the request
  print(f"Response for {url}: {response.status_code}")

# This function tries to discover directories and files in the web application
def discover():
  # Create a thread for each URL in the list
  threads = []
  for directory_or_file in DIRECTORIES_AND_FILES:
    # Create the full URL by combining the base URL and the directory or file
    url = BASE_TARGET + directory_or_file

    # Create a new thread for the URL and add it to the list of threads
    thread = threading.Thread(target=get_request, args=(url,))
    threads.append(thread)

    # Start the thread
    thread.start()

  # Wait for all threads to complete
  for thread in threads:
    thread.join()

def check_internet():
    os.system('ping -c1 google.com > rs_net 2>&1')
    if "0% packet loss" in open('rs_net').read():
        val = 1
    else:
        val = 0
    os.system('rm rs_net > /dev/null 2>&1')
    return val


###################################################! Main Program Starts ###############################################
if __name__ == '__main__':     #? To ensure that the program only runs when it's executed directly, rather than when it's imported as a module.

    # from logo import logo
    # from subdomain import scan
    # from target_validation import validate_input
    from vulnerability_check.xss_check import scan_xss
    from vulnerability_check.sqli_check import scan_sql_injection
    from utilities.links_extractor import crawl

    try:
        target = input("\nPlease enter the domain or ip address of the target that you want to scan: ")

        BASE_TARGET = f"http://{target}"
        DIRECTORIES_AND_FILES = ["/admin", "/login", "/index.html", "/about.html", "/contact.html", "/logout", "/.htpasswd", "/assets", "/news", "/downloads", "/robots.txt", "/search"]
        xss_data_list=[]
        sql_data_list=[]
        print(f"\nStarting {bcolors.CYAN}Web Crawler{bcolors.RESET} on {bcolors.ORANGE}{target}{bcolors.RESET}")
        crawl(BASE_TARGET)

        print(f"\nInitiating {bcolors.CYAN}Cross-Site Scripting Attacks/Vulnerabilty Check{bcolors.RESET} on {bcolors.ORANGE}{target}{bcolors.RESET}")
        with open(f"{target}_internal_links.txt") as fp1:
            for line in fp1:
                xss_data_list.append(scan_xss(line.strip()))
                print("###################################################################")

        print(f"\nInitiating {bcolors.CYAN}SQL Injection Attacks/Vulnerabilty Check{bcolors.RESET} on {bcolors.ORANGE}{target}{bcolors.RESET}")
        with open(f"{target}_internal_links.txt") as fp2:
             for line in fp2:
                 sql_data_list.append(scan_sql_injection(line.strip()))
                 print("###################################################################")
        
        for inner_list in xss_data_list:
            for i,element in enumerate(inner_list):
                print(i,' ',element)
            print()
        print("###################################################################")
        
        for inner_list in sql_data_list:
            for i,element in enumerate(inner_list):
                print(i,' ',element)
            print()
    except KeyboardInterrupt:
        print(f"{bcolors.RED}\n[-] Received Ctrl+C hit, Shutting down...{bcolors.RESET}")
        raise SystemExit
