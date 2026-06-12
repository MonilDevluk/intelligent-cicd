import subprocess
def scan_network(subnet):
    result = subprocess.check_output("nmap " + subnet, shell=True)
    return result.decode()
def check_firewall(port):
    result = subprocess.check_output("iptables -L | grep " + port, shell=True)
    return result.decode()
def monitor_traffic(interface):
    result = subprocess.check_output("tcpdump -i " + interface + " -c 10", shell=True)
    return result.decode()
