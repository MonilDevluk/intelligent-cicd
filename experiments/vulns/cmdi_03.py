import subprocess
import os

def backup_database(db_name):
    subprocess.Popen("pg_dump " + db_name + " > backup.sql", shell=True)

def send_email(to, subject, body):
    os.system(f"echo '{body}' | mail -s '{subject}' {to}")

def resize_image(image_path, width, height):
    cmd = f"convert {image_path} -resize {width}x{height} output.jpg"
    subprocess.check_call(cmd, shell=True)
