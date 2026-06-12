import subprocess
def list_directory(path):
    result = subprocess.check_output(f"ls -la {path}", shell=True)
    return result.decode()
def disk_usage(path):
    result = subprocess.check_output(f"du -sh {path}", shell=True)
    return result.decode()
def file_permissions(path):
    result = subprocess.check_output(f"stat {path}", shell=True)
    return result.decode()
