import queue as Q
from bs4 import BeautifulSoup
import requests
import socket

def is_object_under_same_domain(obj_link, url, src_ip):
    print(obj_link, url, src_ip)
    domain =""
    if url.startswith("https://"):
        domain = url[8:]
        i = domain.find('/')
        if i >0:
            domain = domain[:i]
    elif url.startswith("http://"):
        domain = url[7:]
        i = domain.find('/')
        if i>0:
            domain = domain[:i]

    new_domain = ""
    if url in obj_link:
        return obj_link
    elif obj_link.startswith("https://"):
        new_domain = obj_link[8:]
        i = new_domain.find('/')
        if i>0:
            new_domain = new_domain[:i]
        if domain == new_domain:
            return obj_link
        print(new_domain)
        ip = socket.gethostbyname(new_domain)
        if src_ip != ip:
            return False
        else:
            return obj_link
    elif obj_link.startswith("http://"):
        new_domain = obj_link[7:]
        i = new_domain.find('/')
        if i>0:
            new_domain = new_domain[:i]
        if domain == new_domain:
            return obj_link
        ip = socket.gethostbyname(new_domain)
        if src_ip != ip:
            return False
        else:
            return obj_link
    elif obj_link[0] == '/' and obj_link[1] == '/':
        i = obj_link.find('/', 2)
        if i>0:
            new_domain = obj_link[2:i]
            ip = socket.gethostbyname(new_domain)
            if src_ip != ip:
                return "http:"+obj_link
            else:
                return False
    elif obj_link[0] == '/':
        if url[len(url) - 1] == '/':
            return url[:-1] + obj_link
        else:
            return url + obj_link


def get_largest_obj(url, ip, count):
    print("finding large object on ", url)
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    queue = Q.Queue()
    pageSet = set()
    queue.put(url)
    pageSet.add(url)
    checked = 1
    max_size = 0
    max_url = url
    while not queue.empty() and checked < count:
        cur = queue.get()
        try:
            res = requests.get(cur, headers=headers, allow_redirects=False, timeout=10)
        except Exception as e:
            print(e)
            raise RuntimeError("request error")
        res_code = res.status_code
        if res_code == 301 or res_code == 302:
            if 'Location' in res.headers:
                new_url = res.headers['Location']
                if new_url[0]=='/':
                    new_url = cur + new_url
                queue.put(new_url)
        elif res_code == 200:
            data = res.text
            size = len(res.content)
            if size > max_size:
                max_size = size
                max_url = cur
            soup = BeautifulSoup(data, "html.parser")

            for link in soup.find_all('a'):
                try:
                    obj_link = link.get('href')
                    if obj_link is not None:
                        obj_url = is_object_under_same_domain(obj_link, url, ip)
                        if obj_url != False and obj_url is not None:
                            if obj_url not in pageSet:
                                queue.put(obj_url)
                                pageSet.add(obj_url)
                                checked = checked + 1
                except Exception as e:
                    print(e)
                    continue
    print("found large object ", max_url, ", size is ", max_size)
    return [max_size, max_url]