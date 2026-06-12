import subprocess

def check_ssl(domain):
    result = subprocess.check_output("openssl s_client -connect " + domain + ":443", shell=True)
    return result.decode()

def run_script(script_path):
    subprocess.run("bash " + script_path, shell=True)

def check_syntax(filename):
    result = subprocess.check_output("python3 -m py_compile " + filename, shell=True)
    return result.decode()
