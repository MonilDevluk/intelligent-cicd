import subprocess
import os

def check_disk_usage(path):
    result = subprocess.check_output("du -sh " + path, shell=True)
    return result.decode()

def kill_process(process_name):
    os.system("pkill " + process_name)

def change_permissions(filepath, mode):
    subprocess.run("chmod " + mode + " " + filepath, shell=True)
