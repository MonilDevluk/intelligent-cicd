import os
import subprocess

def ping_host(hostname):
    os.system("ping -c 1 " + hostname)

def list_files(directory):
    output = subprocess.check_output("ls " + directory, shell=True)
    return output.decode()

def get_file_info(filename):
    result = os.popen("file " + filename).read()
    return result
