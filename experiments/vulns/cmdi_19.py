import subprocess
def archive_directory(directory, archive_name):
    result = subprocess.check_output("tar -czf " + archive_name + " " + directory, shell=True)
    return result.decode()
def extract_archive(archive_name, destination):
    result = subprocess.check_output("tar -xzf " + archive_name + " -C " + destination, shell=True)
    return result.decode()
def list_archive(archive_name):
    result = subprocess.check_output("tar -tzf " + archive_name, shell=True)
    return result.decode()
