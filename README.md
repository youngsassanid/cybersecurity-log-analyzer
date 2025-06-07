# cybersecurity-log-analyzer

A powerful Python tool for detecting and visualizing brute force attacks from system authentication logs.

## Features

* Parses Linux `auth.log` for failed login attempts
* Visualizes top offending IPs using `matplotlib`
* Optional GeoIP location lookup
* Aggregates usernames and timestamps per IP
* Generates detailed text report (`attack_report.txt`)
* Sends email alerts when attack thresholds are exceeded

## Requirements

Install the required Python libraries:

```bash
pip install matplotlib geoip2
```

## GeoIP Location

1. Sign up at [MaxMind](https://www.maxmind.com) for a free account.
2. Download the **GeoLite2-City.mmdb** file.
3. Place it in the project directory or update the `GEOIP_DB_PATH` in the script.

## Email Alerts

To enable email alerts:

1. Enable 2-Step Verification for your Gmail account.
2. Generate an [App Password](https://myaccount.google.com/apppasswords).
3. Update these fields in the script:

```python
EMAIL_SENDER = 'your_email@gmail.com'
EMAIL_PASSWORD = 'your_app_password'
EMAIL_RECEIVER = 'receiver_email@example.com'
```

## Usage

### Basic

```bash
python cybersecurity_log_analyzer.py /path/to/auth.log
```

### With GeoIP

```bash
python cybersecurity_log_analyzer.py /path/to/auth.log --geoip
```

## Output

* `brute_force_attempts.png`: Bar chart of top 10 IPs
* `attack_report.txt`: Report with location, usernames, and timestamps
* Email alert (optional): Sent if threshold is exceeded by an IP


---

## 🌟 Star This Project

If you found this useful, please give it a ⭐️ on GitHub!
