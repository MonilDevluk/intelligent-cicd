import subprocess
def send_email(recipient, subject, body):
    result = subprocess.check_output("echo " + body + " | mail -s " + subject + " " + recipient, shell=True)
    return result.decode()
def check_dns(domain):
    result = subprocess.check_output("dig " + domain, shell=True)
    return result.decode()
def http_request(url):
    result = subprocess.check_output("curl " + url, shell=True)
    return result.decode()
