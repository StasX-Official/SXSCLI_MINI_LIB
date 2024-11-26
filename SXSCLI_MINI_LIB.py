import base64
from Crypto.Cipher import AES
import hashlib
import os
import ssl
import socket
import requests
import dns.resolver
import whois
from datetime import datetime
import time                
import subprocess
import ipaddress
from ipaddress import ip_network

#SXSERVISECLI PYTHON LIBRARY
#SXSCLI-MINI
#Copyright (c) 2024 StasX all rights reserved.

class SXSCLI:
    def __init__(self):
        self.version = "0.0.9"
        self.relise_ = "b"
        self.author = "SX"
        self.com = "api.sxservisecli.tech"
        self.project_id = None
        self.project_key = None
        self.owner_nickname = None
        self.owner_email = None
        self.owner_token = None
        
    def config(self, project_id, project_key, owner_token, settings):
        if len(project_id) <= 5 or len(project_key) <= 5 or len(owner_token) <= 15:
            print("SXSCLI-MINI: Config Error. Please check your project_id, project_key, project_token.")
        else:
            self.project_id = project_id
            self.project_key = project_key
            self.owner_token = owner_token
            SXSCLI.System.s2(self)
    
    class System:
        def s2(self):
            encrypted_token=self.owner_token
            decoded_token = base64.b64decode(encrypted_token)
            nonce, tag, ciphertext = decoded_token[:16], decoded_token[16:32], decoded_token[32:]
            aes_key = hashlib.sha256(b"static_key").digest()[:16]
            cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            token = cipher.decrypt_and_verify(ciphertext, tag).decode()
            parts = token.split('$')
            self.owner_email = parts[2]
            self.owner_nickname = parts[3]
            self.owner_token = parts[4]
            
    class cmd:
        def get_mx_records(self,domain):
            import dns.resolver
            try:
                records = dns.resolver.resolve(domain, 'MX')
                return [record.exchange.to_text() for record in records]
            except Exception as e:
                return f"Error: {e}"

        def find_hidden_services(self,ip):
            common_ports = [21, 22, 23, 25, 80, 110, 143, 443]
            return SXSCLI.cmd.scan_open_ports(ip, common_ports)

        def scan_open_ports(self,ip, ports):
            import socket
            open_ports = []
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
            return open_ports

        def trace_route(self,ip):
            from subprocess import Popen, PIPE
            process = Popen(['tracert', ip], stdout=PIPE)
            return process.stdout.read().decode()

        def get_ttl(self,ip):
            import subprocess
            result = subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.PIPE)
            return result.stdout.decode().split("ttl=")[1].split(" ")[0]

        def get_subnet(self,ip, mask):
            from ipaddress import ip_network
            return ip_network(f"{ip}/{mask}", strict=False)

        def get_ptr_record(self,ip):
            import dns.resolver
            try:
                addr = dns.reversename.from_address(ip)
                return str(dns.resolver.resolve(addr, 'PTR')[0])
            except Exception as e:
                return f"Error: {e}"

        def generate_random_ips(self,count):
            import random
            return [f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}" for _ in range(count)]

        def check_ssl(self,domain):
            import ssl
            import socket
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        return ssock.getpeercert()
            except Exception as e:
                return f"Error: {e}"


        def scan_ip_range(self,start_ip, end_ip, port=80):
            open_ips = []
            try:
                for ip in ip_network(f"{start_ip}-{end_ip}"):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    if sock.connect_ex((str(ip), port)) == 0:
                        open_ips.append(str(ip))
                    sock.close()
                return open_ips if open_ips else "No open IPs found in the range."
            except Exception as e:
                return f"Error: {e}"

        def get_ip_by_domain(self,domain):
            try:
                ip = socket.gethostbyname(domain)
                return f"The IP address of {domain} is {ip}."
            except socket.gaierror as e:
                return f"Error resolving domain: {e}"

        def get_local_ips(self):
            local_ips = []
            try:
                hostname = socket.gethostname()
                local_ips.append(socket.gethostbyname(hostname))
                for ip in socket.getaddrinfo(hostname, None):
                    local_ips.append(ip[4][0])
                return list(set(local_ips))
            except Exception as e:
                return f"Error: {e}"

        def check_port(self,ip, port):
            try:
                with socket.create_connection((ip, port), timeout=1) as conn:
                    return f"Port {port} on {ip} is open"
            except socket.error:
                return f"Port {port} on {ip} is closed"
                
        def is_private_ip(self,ip):
            private_ranges = [
                ipaddress.IPv4Network("10.0.0.0/8"),
                ipaddress.IPv4Network("172.16.0.0/12"),
                ipaddress.IPv4Network("192.168.0.0/16"),
                ipaddress.IPv4Network("127.0.0.0/8")
            ]
            ip_obj = ipaddress.IPv4Address(ip)
            for network in private_ranges:
                if ip_obj in network:
                    return f"IP {ip} is private"
            return f"IP {ip} is public"

        def get_ip_geolocation(self,ip):
            try:
                response = requests.get(f"https://ipinfo.io/{ip}/json")
                if response.status_code == 200:
                    data = response.json()
                    location = f"City: {data.get('city', 'N/A')}, Region: {data.get('region', 'N/A')}, Country: {data.get('country', 'N/A')}"
                    return f"Geolocation of {ip}: {location}"
                return "Failed to fetch geolocation"
            except requests.exceptions.RequestException as e:
                return f"Error: {e}"

        
        def ping_ip(self,ip, timeout=1):
            try:
                response = subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
                if response.returncode == 0:
                    return f"IP {ip} is reachable"
                return f"IP {ip} is not reachable"
            except Exception as e:
                return f"Ping error: {e}"

        def get_local_ip(self):
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                return f"Local IP: {local_ip}"
            except socket.error as e:
                return f"Error getting local IP: {e}"

        def get_public_ip(self):
            try:
                response = requests.get('https://api.ipify.org?format=json')
                if response.status_code == 200:
                    return f"Public IP: {response.json()['ip']}"
                return "Failed to fetch public IP"
            except requests.exceptions.RequestException as e:
                return f"Error: {e}"

        def check_api_methods(self, api_url):
            if self.poject_id != None and self.project_key != None and self.owner_token != None and self.owner_email != None and self.owner_nickname != None:
                try:
                    response = requests.get(f"{api_url}/methods")
                    if response.status_code == 200:
                        methods = response.json().get("methods", [])
                        return f"API supports the following methods: {', '.join(methods)}"
                    return f"Failed to fetch methods: {response.status_code}"
                except requests.exceptions.RequestException:
                    return "Error checking API methods"
            else:
                print("SXSCLI-MINI: Config Error. Please check your config.")

        def check_api_response_time(self, api_url):
            if self.poject_id != None and self.project_key != None and self.owner_token != None and self.owner_email != None and self.owner_nickname != None:
                try:
                    start_time = time.time()
                    response = requests.get(api_url)
                    end_time = time.time()
                    response_time = end_time - start_time
                    return f"API response time: {response_time:.2f} seconds"
                except requests.exceptions.RequestException:
                    return "Error checking API response time"
            else:
                print("SXSCLI-MINI: Config Error. Please check your config.")

        def check_open_ports(self,domain, ports=[80, 443]):
            if self.poject_id != None and self.project_key != None and self.owner_token != None and self.owner_email != None and self.owner_nickname != None:
                open_ports = []
                for port in ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((domain, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                return open_ports
            else:
                print("SXSCLI-MINI: Config Error. Please check your config.")
        
        def check_api_status(self,api_url):
            if self.poject_id != None and self.project_key != None and self.owner_token != None and self.owner_email != None and self.owner_nickname != None:
                try:
                    response = requests.get(api_url)
                    if response.status_code == 200:
                        return "API is available"
                    return f"API returned status code {response.status_code}"
                except requests.exceptions.RequestException:
                    return "API is not available"
            else:
                print("SXSCLI-MINI: Config Error. Please check your config.")
            
        def check_page_load_time(self,url):
            if self.poject_id != None and self.project_key != None and self.owner_token != None and self.owner_email != None and self.owner_nickname != None:
                start_time = time.time()
                response = requests.get(url)
                end_time = time.time()
                load_time = end_time - start_time
                return load_time
            else:
                print("SXSCLI-MINI: Config Error. Please check your config.")
        
        def domain_whois(domain):
                result_str = ""

                try:
                    domain_info = whois.whois(domain)
                    result_str += "Domain WHOIS info:\n"
                    for key, value in domain_info.items():
                        result_str += f" - {key}: {value}\n"
                except Exception as e:
                    result_str += f"{datetime.now().strftime('%d_%m_%Y_%H_%M')} - Component WHOIS: WHOIS error: {e}\n"

                try:
                    result_str += "\nDNS Records:\n"
                    a_records = dns.resolver.resolve(domain, 'A', lifetime=3)  
                    for a in a_records:
                        result_str += f" - A Record: {a}\n"

                    mx_records = dns.resolver.resolve(domain, 'MX', lifetime=3)
                    for mx in mx_records:
                        result_str += f" - MX Record: {mx.exchange} Priority: {mx.preference}\n"

                    txt_records = dns.resolver.resolve(domain, 'TXT', lifetime=3)
                    for txt in txt_records:
                        result_str += f" - TXT Record: {txt.to_text()}\n"

                    cname_record = dns.resolver.resolve(domain, 'CNAME', lifetime=3)
                    for cname in cname_record:
                        result_str += f" - CNAME Record: {cname}\n"
                except (dns.resolver.Timeout, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
                    result_str += f"{datetime.now().strftime('%d_%m_%Y_%H_%M')} - Component WHOIS: DNS Record error: Timeout or No Answer\n"
                except Exception as e:
                    result_str += f"{datetime.now().strftime('%d_%m_%Y_%H_%M')} - Component WHOIS: DNS Record error: {e}\n"


                try:
                    result_str += "\nSSL Certificate:\n"
                    context = ssl.create_default_context()
                    with socket.create_connection((domain, 443)) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                            result_str += f" - Issuer: {cert['issuer']}\n"
                            result_str += f" - Valid from: {cert['notBefore']}\n"
                            result_str += f" - Valid until: {cert['notAfter']}\n"
                            result_str += f" - Serial Number: {cert['serialNumber']}\n"
                            result_str += f" - Signature Algorithm: {cert['signatureAlgorithm']}\n"
                except Exception as e:
                    result_str += f"{datetime.now().strftime('%d_%m_%Y_%H_%M')} - Component WHOIS: SSL error: {e}\n"

                try:
                    result_str += "\nEmail Security Records:\n"
                    txt_records = dns.resolver.resolve(domain, 'TXT')
                    for txt in txt_records:
                        if 'v=spf' in txt.to_text():
                            result_str += f" - SPF Record: {txt.to_text()}\n"
                        if 'v=DMARC' in txt.to_text():
                            result_str += f" - DMARC Record: {txt.to_text()}\n"

                    dkim_records = dns.resolver.resolve(f"{domain}._domainkey.{domain}", 'TXT')
                    for dkim in dkim_records:
                        result_str += f" - DKIM Record: {dkim.to_text()}\n"
                except Exception as e:
                    result_str += f"{datetime.now().strftime('%d_%m_%Y_%H_%M')} - Component WHOIS: Email Security Record error: {e}\n"

                def check_http_https(domain):
                    try:
                        response = requests.get(f"http://{domain}")
                        if response.status_code == 200:
                            return "HTTP is accessible"
                        return f"HTTP returned status code {response.status_code}"
                    except requests.exceptions.RequestException:
                        return "HTTP is not accessible"
                    finally:
                        try:
                            response = requests.get(f"https://{domain}")
                            if response.status_code == 200:
                                return "HTTPS is accessible"
                            return f"HTTPS returned status code {response.status_code}"
                        except requests.exceptions.RequestException:
                            return "HTTPS is not accessible"

                result_str += f"\nHTTP/HTTPS Check: {check_http_https(domain)}\n"

                def check_privacy(domain_info):
                    if domain_info.get("privacy"):
                        return "Domain has private registration"
                    return "Domain has public registration"

                result_str += f"\nWHOIS Privacy: {check_privacy(domain_info)}\n"

                def check_domain_reputation(domain):
                    url = f"https://www.mywot.com/en/scorecard/{domain}"
                    try:
                        response = requests.get(url)
                        if response.status_code == 200:
                            return "Reputation data fetched successfully"
                        return f"Reputation returned status code {response.status_code}"
                    except requests.exceptions.RequestException:
                        return "Reputation check failed"

                result_str += f"\nReputation Check: {check_domain_reputation(domain)}\n"

                def check_technologies(domain):
                    url = f"http://{domain}"
                    try:
                        response = requests.get(url)
                        headers = response.headers
                        technologies = []
                        if 'X-Powered-By' in headers:
                            technologies.append(f"X-Powered-By: {headers['X-Powered-By']}")
                        if 'Server' in headers:
                            technologies.append(f"Server: {headers['Server']}")
                        return ', '.join(technologies) if technologies else "No technology data found."
                    except requests.exceptions.RequestException:
                        return "Technology check failed"

                result_str += f"\nTechnology Check: {check_technologies(domain)}\n"

                def check_caa_records(domain):
                    try:
                        caa_records = dns.resolver.resolve(domain, 'CAA')
                        if caa_records:
                            return f"CAA Records: {', '.join([str(record) for record in caa_records])}"
                        return "No CAA records found."
                    except Exception:
                        return "CAA check failed."

                result_str += f"\nCAA Records Check: {check_caa_records(domain)}\n"
                result_str += f"\n\nSXSCLI-MINI: Domain WHOIS completed.\n"
                result_str += f"\n\nIt is forbidden to use for illegal purposes. Conditions apply. (Open source application. Library.)\n"
                result_str += f"\n\nSXSCLI: https://www.sxservisecli.tech/ or https://github.com/StasX-Official/SXServiseCLI\n"
                result_str += f"\n\nSXSCLI-MINI: Domain WHOIS completed.\n"
                result_str += f"\n\nPowered by SXServiseCLI!\n"
                return result_str