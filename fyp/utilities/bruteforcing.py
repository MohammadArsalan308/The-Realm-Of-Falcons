import requests
import threading

scan_data_list = [] 

# This function sends a GET request to the specified URL and prints the response
# DIRECTORIES_AND_FILES = ["/admin", "/login", "/index.html", "/about.html", "/contact.html", "/logout", "/.htpasswd", "/assets", "/news", "/downloads", "/robots.txt", "/search"]
   
def get_request(url):
  # Send the GET request to the specified URL
  response = requests.get(url)
  if response.status_code != 404:
    scan_data_list.append({'url': url, 'response_status_code': response.status_code})
 

## This function tries to discover directories and files in the web application
def discover(target):
  # Create a thread for each URL in the list
  threads = []
  BASE_TARGET = f"http://{target}"

  with open("C:/Users/Altaf/Desktop/fyp/wordlists/common.lst", "r") as wordlist_file: 
    for directory_or_file in wordlist_file: 
      word = directory_or_file.strip()

      # Create the full URL by combining the base URL and the directory or file
      url = f"{BASE_TARGET}/{word}"

      # Create a new thread for the URL and add it to the list of threads
      thread = threading.Thread(target=get_request, args=(url,))
      # Start the thread
      thread.start()
      threads.append(thread)

  # Wait for all threads to complete
  for thread in threads:
    thread.join()

def bruteforcings(target):
    scan_data_list.clear()
    discover(target)
    return scan_data_list
