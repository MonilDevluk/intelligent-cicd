import subprocess

def convert_file(input_file, output_file):
    subprocess.call("convert " + input_file + " " + output_file, shell=True)

def compress_file(filename):
    subprocess.run("gzip " + filename, shell=True)

def check_port(host, port):
    result = subprocess.check_output("nc -zv " + host + " " + str(port), shell=True)
    return result.decode()
