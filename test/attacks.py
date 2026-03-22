import socket
import time
import random

TARGET_IP = "127.0.0.1"

PORTS = [22, 80, 443, 8080, 3306, 21, 25, 53]

def port_scan():
    for port in PORTS:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((TARGET_IP, port))
            s.close()
        except:
            pass
        time.sleep(0.1)

def brute_force():
    for _ in range(20):
        try:
            s = socket.socket()
            s.connect((TARGET_IP, 22))
            s.close()
        except:
            pass
        time.sleep(0.05)

def random_attack():
    for _ in range(30):
        port = random.choice(PORTS)
        try:
            s = socket.socket()
            s.connect((TARGET_IP, port))
            s.close()
        except:
            pass
        time.sleep(0.1)

if __name__ == "__main__":
    print("Generating traffic...")

    port_scan()
    brute_force()
    random_attack()

    print("Done.")