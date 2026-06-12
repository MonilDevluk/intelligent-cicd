import os

def read_file(filename):
    base_dir = "/var/www/files/"
    file_path = base_dir + filename
    with open(file_path, "r") as f:
        return f.read()

def get_user_file(username, filename):
    path = os.path.join("/home", username, filename)
    with open(path, "r") as f:
        return f.read()
