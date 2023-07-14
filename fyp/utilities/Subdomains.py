import threading
import socket
subdomain_list=[]
thread_list = [] 

def scan(subdomain): 
	try:
		ip = socket.gethostbyname(subdomain) 
		subdomain_list.append({'subdomain':subdomain}) 
		#print("[+] Discovered subdomain:",subdomain)
	except: 
		pass
        
def subdomains(target):     
    with open("C:/Users/Altaf/Desktop/fyp/wordlists/subdomains.lst", "r") as wordlist_file: 
        subdomain_list.clear()
        for line in wordlist_file: 
            word = line.strip()
            subdomain = word + "." + target
            t = threading.Thread(target=scan, args=(subdomain,))
            t.start()
            thread_list.append(t)
    for thread in thread_list:
        thread.join()
    return subdomain_list