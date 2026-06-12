import subprocess
def run_script(script_name):
    result = subprocess.run("bash " + script_name, shell=True, capture_output=True)
    return result.stdout.decode()
def kill_process(pid):
    result = subprocess.run("kill " + pid, shell=True, capture_output=True)
    return result.stdout.decode()
def change_permissions(path, mode):
    result = subprocess.run("chmod " + mode + " " + path, shell=True, capture_output=True)
    return result.stdout.decode()
