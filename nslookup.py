#! /usr/bin/python3
from subprocess import Popen, PIPE
from re import findall
 
 
class NSLookup:
    def __init__(self, domains):
        self.domains = domains
        self.canonical = r"\s+canonical\s+name\s+=\s+(.*)\s+"
        self.address = r"Address:\s+(\d+.\d+.\d+.\d+)\s+"
 
    def examine(self):
        for d in self.domains:
            data = {'domain': d, 'names': [], 'ips': []}
            cmd = ["nslookup",  d]
            out = Popen(cmd, stdout=PIPE).communicate()[0].decode()
            server_names = findall(self.canonical, out)
            server_ips = findall(self.address, out)
            for name in server_names:
                data['names'].append(name)
            for ip in server_ips:
                data['ips'].append(ip)
            yield data
 
 
if __name__ == "__main__":
    # EXAMPLE CLIENT:
    domain_list = [
        'kenmacpherson.com', 'c-s6.com', 't836.com', 'nonexistentdomain123456789.com'
    ]
    for test in NSLookup(domain_list).examine():
        print(test)