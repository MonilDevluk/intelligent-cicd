import subprocess

def run_tests(test_file):
    result = subprocess.check_output("pytest " + test_file, shell=True)
    return result.decode()

def install_package(package_name):
    subprocess.run("pip install " + package_name, shell=True)

def git_clone(repo_url, dest):
    subprocess.call("git clone " + repo_url + " " + dest, shell=True)
