import subprocess

def search_logs(keyword):
    result = subprocess.check_output("grep " + keyword + " /var/log/app.log", shell=True)
    return result.decode()

def count_lines(filename):
    result = subprocess.check_output("wc -l " + filename, shell=True)
    return result.decode()

def find_files(pattern, directory):
    result = subprocess.check_output("find " + directory + " -name " + pattern, shell=True)
    return result.decode()
