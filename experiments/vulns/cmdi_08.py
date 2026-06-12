import subprocess
import os

def get_cpu_info():
    result = subprocess.check_output("cat /proc/cpuinfo | grep 'model name'", shell=True)
    return result.decode()

def monitor_process(process_name):
    result = subprocess.check_output("ps aux | grep " + process_name, shell=True)
    return result.decode()

def get_memory_usage(process_id):
    os.system("cat /proc/" + process_id + "/status | grep VmRSS")
