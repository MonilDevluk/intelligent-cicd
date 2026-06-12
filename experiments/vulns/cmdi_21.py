import subprocess
def check_service(service_name):
    result = subprocess.check_output("systemctl status " + service_name, shell=True)
    return result.decode()
def restart_service(service_name):
    result = subprocess.check_output("systemctl restart " + service_name, shell=True)
    return result.decode()
def view_logs(service_name):
    result = subprocess.check_output("journalctl -u " + service_name + " --no-pager", shell=True)
    return result.decode()
