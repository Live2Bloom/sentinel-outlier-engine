import csv
import time
import random

def generate_test_logs():
    ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"]
    attacker_brute = "172.16.0.5"
    attacker_exfil = "10.0.0.99"

    with open('server_logs.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        # Normal traffic for 5 minutes
        for _ in range(200):
            writer.writerow([time.time(), random.choice(ips), "GET /index.html", 200, random.randint(500, 1500)])

        # Attack 1: Brute Force (High requests, high errors, low bytes)
        for _ in range(50):
            writer.writerow([time.time(), attacker_brute, "POST /login", 401, 100])

        # Attack 2: Data Exfiltration (Low requests, low errors, MASSIVE bytes)
        for _ in range(10):
            writer.writerow([time.time(), attacker_exfil, "GET /database_backup.sql", 200, 5000000])

if __name__ == "__main__":
    generate_test_logs()
    print("server_logs.csv generated. Run your C program now!")
