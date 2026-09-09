import os

def ping_host(hostname):
    os.system("ping -c 1 " + hostname)

if __name__ == "__main__":
    ping_host("127.0.0.1")
