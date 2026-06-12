import subprocess
def ping_host(host):
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return result.decode()
def traceroute_host(host):
    result = subprocess.check_output("traceroute " + host, shell=True)
    return result.decode()
def nslookup_host(host):
    result = subprocess.check_output("nslookup " + host, shell=True)
    return result.decode()
