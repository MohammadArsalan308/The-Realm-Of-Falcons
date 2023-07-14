from requests_html import HTMLSession
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import colorama

# init the colorama module
colorama.init()

GREEN = colorama.Fore.GREEN
GRAY = colorama.Fore.LIGHTBLACK_EX
RESET = colorama.Fore.RESET
YELLOW = colorama.Fore.YELLOW
data=[]

# initialize the set of links (unique links)
internal_urls = set()
external_urls = set()

total_urls_visited = 0
max_urls = 60

def is_valid(url):
	"""
	Checks whether `url` is a valid URL.
	"""
	parsed = urlparse(url)
	return bool(parsed.netloc) and bool(parsed.scheme)


def get_all_website_links(url):
	"""
	Returns all URLs that is found on `url` in which it belongs to the same website
	"""
	# all URLs of `url`
	urls = set()
	# initialize an HTTP session
	session = HTMLSession()
	# make HTTP request & retrieve response
	response = session.get(url)
	# execute Javascript
	try:
		response.html.render()
	except:
		pass
	soup = BeautifulSoup(response.html.html, "html.parser")
	
	# Let's get all HTML a tags (anchor tags that contains all the links of the web page)
	for a_tag in soup.findAll("a"):
		href = a_tag.attrs.get("href")
		if href == "" or href is None:
			# href empty tag
			continue
		# join the URL if it's relative (not absolute link)
		href = urljoin(url, href)
		
		parsed_href = urlparse(href)
		# remove URL GET parameters, URL fragments, etc. Since this will cause redundancy in the set
		href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
		domain_name = urlparse(url).netloc
		if not is_valid(href):
			# not a valid URL
			continue
		if href in internal_urls:
			# already in the set
			continue
		if domain_name not in href:
			# external link
			if href not in external_urls:
				print(f"{GRAY}[!] External link: {href}{RESET}")
				external_urls.add(href)
			continue
		print(f"{GREEN}[*] Internal link: {href}{RESET}")
		urls.add(href)
		internal_urls.add(href)
		data.append(href)
		
	return urls


def crawl_data(url, max_urls):
	"""
	Crawls a web page and extracts all links.
	You'll find all links in `external_urls` and `internal_urls` global set variables.
	params:
		max_urls (int): number of max urls to crawl.
	"""
	global total_urls_visited
	total_urls_visited += 1
	print(f"{YELLOW}[*] Crawling: {url}{RESET}")
	links = get_all_website_links(url)
	for link in links:
		if total_urls_visited > max_urls:
			break
		crawl_data(link, max_urls=max_urls)


def crawl(url):
	data.clear()
	internal_urls.clear()
	external_urls.clear()
	domain_name = urlparse(url).netloc
	crawl_data(url, max_urls)

	print("[+] Total Internal links:", len(internal_urls))
	print("[+] Total External links:", len(external_urls))
	print("[+] Total URLs:", len(external_urls) + len(internal_urls))
	print("[+] Total crawled URLs:", max_urls)
	print("\n")
	print(data)

	# save the internal links to a file
	with open(f"{domain_name}_internal_links.txt", "w") as f:
		print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
		for internal_link in internal_urls:
				print(internal_link.strip(), file=f)
	# save the external links to a file
	with open(f"{domain_name}_external_links.txt", "w") as f:
			for external_link in external_urls:
				print(external_link.strip(), file=f)

	return data

# data=crawl("http://testphp.vulnweb.com")
# print(data)
# print(len(data))