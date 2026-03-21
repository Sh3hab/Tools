import subprocess
import platform
import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init


init(autoreset=True)

def get_os_guess(ttl):
   
    if not ttl: return f"{Fore.YELLOW}unknown"
    ttl = int(ttl)
    if ttl <= 64:
        return f"{Fore.CYAN}Android"
    elif ttl <= 128:
        return f"{Fore.BLUE}Windows"
    else:
        return f"{Fore.MAGENTA}Network Device"

def get_hostname(ip):
 
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name if name else "Unknown"
    except:
        return "---"

def ping_device(ip):
    
    system_os = platform.system().lower()

    param = ["ping", "-n", "1", "-w", "800", ip] if system_os == "windows" else ["ping", "-c", "1", "-W", "1", ip]
    
    try:
        output = subprocess.check_output(param, stderr=subprocess.STDOUT, universal_newlines=True)
        
        ttl = None
        for line in output.lower().split('\n'):
            if "ttl=" in line:
                ttl = line.split("ttl=")[1].split()[0].strip()
                break
        
        hostname = get_hostname(ip)
        os_info = get_os_guess(ttl)
        
        return {"ip": ip, "host": hostname, "os": os_info, "ttl": ttl}
    except:
        return None

def scan_network():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"

    base_ip = ".".join(local_ip.split('.')[:-1])
    
    print(f"\n{Fore.GREEN}[+] Network scanning start: {Fore.WHITE}{base_ip}.0/24")
    print(f"{Fore.CYAN}{'='*65}")
    print(f"{Fore.YELLOW}{'IP Address':<15} | {'Hostname':<22} | {'OS Guess':<15}")
    print(f"{Fore.CYAN}{'='*65}")

    
    with ThreadPoolExecutor(max_workers=250) as executor:
        ips = [f"{base_ip}.{i}" for i in range(1, 255)]
        results = executor.map(ping_device, ips)
        
        found_count = 0
        for res in results:
            if res:
                found_count += 1
                print(f"{Fore.WHITE}{res['ip']:<15} | {Fore.GREEN}{res['host'][:22]:<22} | {res['os']}")
    
    print(f"{Fore.CYAN}{'='*65}")
    print(f"{Fore.GREEN}[!] finished, connected Device's: {found_count}")

if __name__ == "__main__":
    scan_network()
