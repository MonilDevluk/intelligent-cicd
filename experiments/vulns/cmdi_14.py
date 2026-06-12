import subprocess
def search_logs(keyword):
    result = subprocess.check_output("grep %s /var/log/syslog" % keyword, shell=True)
    return result.decode()
def find_file(filename):
    result = subprocess.check_output("find / -name %s" % filename, shell=True)
    return result.decode()
def check_port(port):
    result = subprocess.check_output("netstat -an | grep %s" % port, shell=True)
    return result.decode()
