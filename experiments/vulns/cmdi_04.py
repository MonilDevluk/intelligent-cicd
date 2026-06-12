import subprocess

def scan_network(ip_range):
    result = subprocess.check_output("nmap " + ip_range, shell=True)
    return result.decode()

def download_file(url, dest):
    subprocess.run("wget " + url + " -O " + dest, shell=True)

def extract_archive(archive, dest):
    subprocess.call("tar -xf " + archive + " -C " + dest, shell=True)
