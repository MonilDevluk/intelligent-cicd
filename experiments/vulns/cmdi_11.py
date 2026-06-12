import subprocess

def encode_file(filename, encoding):
    result = subprocess.check_output("base64 " + filename, shell=True)
    return result.decode()

def sort_file(filename):
    result = subprocess.check_output("sort " + filename, shell=True)
    return result.decode()

def word_count(filename):
    result = subprocess.check_output("wc -w " + filename, shell=True)
    return result.decode()
