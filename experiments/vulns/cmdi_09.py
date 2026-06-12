import subprocess

def copy_file(src, dst):
    subprocess.run("cp " + src + " " + dst, shell=True)

def move_file(src, dst):
    subprocess.run("mv " + src + " " + dst, shell=True)

def delete_file(filepath):
    subprocess.run("rm " + filepath, shell=True)
