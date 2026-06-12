import os
def backup_file(filename):
    os.system("cp " + filename + " /tmp/backup/")
def delete_file(filename):
    os.system("rm " + filename)
def compress_file(filename):
    os.system("gzip " + filename)
