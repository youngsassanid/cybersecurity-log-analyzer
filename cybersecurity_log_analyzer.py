# cybersecurity_log_analyzer.py

import re
import matplotlib.pyplot as plt
from collections import defaultdict, Counter
import argparse
import socket
import os
import geoip2.database
import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ========== Configuration ==========
GEOIP_DB_PATH = 'GeoLite2-City.mmdb'  # Download from MaxMind (free account)
EMAIL_ALERTS_ENABLED = True
EMAIL_THRESHOLD = 20  # Number of attempts to trigger alert
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_SENDER = 'your_email@gmail.com'
EMAIL_PASSWORD = 'your_app_password'
EMAIL_RECEIVER = 'receiver_email@example.com'

# ========== Log Parsing Functions ==========
def parse_auth_log(filepath):
    brute_force_attempts = defaultdict(int)
    usernames = defaultdict(set)
    timestamps = defaultdict(list)
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = re.search(r'(\w{3}\s+\d+\s[\d:]+)\s.*Failed password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                timestamp = match.group(1)
                username = match.group(3)
                ip = match.group(4)
                brute_force_attempts[ip] += 1
                usernames[ip].add(username)
                timestamps[ip].append(timestamp)

    return brute_force_attempts, usernames, timestamps

# ========== GeoIP Lookup ==========
def get_location(ip):
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip)
            city = response.city.name or 'Unknown'
            country = response.country.name or 'Unknown'
            return f"{city}, {country}"
    except:
        return "Unknown"

# ========== Visualization ==========
def plot_attempts(attempts):
    sorted_attempts = dict(Counter(attempts).most_common(10))
    ips = list(sorted_attempts.keys())
    counts = list(sorted_attempts.values())

    plt.figure(figsize=(12, 6))
    plt.bar(ips, counts, color='red')
    plt.xlabel('IP Address')
    plt.ylabel('Failed Login Attempts')
    plt.title('Top 10 Brute Force IPs')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('brute_force_attempts.png')
    plt.show()

# ========== Report Generation ==========
def generate_report(attempts, usernames, timestamps):
    with open('attack_report.txt', 'w') as report:
        report.write("Brute Force Attack Report\n")
        report.write("Generated: " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
        for ip in sorted(attempts, key=attempts.get, reverse=True):
            report.write(f"IP: {ip}\n")
            report.write(f"Location: {get_location(ip)}\n")
            report.write(f"Attempts: {attempts[ip]}\n")
            report.write(f"Usernames Tried: {', '.join(usernames[ip])}\n")
            report.write(f"Timestamps: {', '.join(timestamps[ip][:3])} ...\n")
            report.write("-"*40 + "\n")
    print("Report saved as attack_report.txt")

# ========== Email Alerts ==========
def send_email_alert(ip, count, usernames):
    subject = f"Security Alert: Brute Force Attempt from {ip}"
    body = f"IP: {ip}\nAttempts: {count}\nUsernames: {', '.join(usernames)}\nLocation: {get_location(ip)}"

    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        print(f"Email alert sent for {ip}!")
    except Exception as e:
        print(f"Failed to send email: {e}")

# ========== CLI ==========
def main():
    parser = argparse.ArgumentParser(description='Cybersecurity Log Analyzer')
    parser.add_argument('logfile', help='Path to the auth log file')
    parser.add_argument('--geoip', action='store_true', help='Include GeoIP location lookup')
    args = parser.parse_args()

    if args.geoip and not os.path.exists(GEOIP_DB_PATH):
        print("GeoIP database not found. Download from MaxMind and set GEOIP_DB_PATH.")
        return

    print(f"Analyzing {args.logfile}...")
    attempts, usernames, timestamps = parse_auth_log(args.logfile)

    if not attempts:
        print("No brute force attempts found.")
    else:
        print("Top IPs by brute force attempts:")
        for ip, count in sorted(attempts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"{ip}: {count} attempts")
            if EMAIL_ALERTS_ENABLED and count >= EMAIL_THRESHOLD:
                send_email_alert(ip, count, usernames[ip])

        plot_attempts(attempts)
        generate_report(attempts, usernames, timestamps)

if __name__ == '__main__':
    main()
