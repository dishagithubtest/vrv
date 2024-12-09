import re
import csv
from collections import defaultdict

# Configuration
FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = 'sample.log'
CSV_OUTPUT_FILE = 'log_analysis_results.csv'


def parse_log_file(log_file):
    """
    Parses the log file and returns extracted data.
    """
    ip_request_count = defaultdict(int)
    endpoint_request_count = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*\] "(?P<method>\w+) (?P<endpoint>\S+) HTTP/\d\.\d" (?P<status>\d{3}) .*'
    )

    with open(log_file, 'r') as file:
        for line in file:
            match = log_pattern.match(line)
            if match:
                ip = match.group('ip')
                endpoint = match.group('endpoint')
                status = match.group('status')

                # Count requests per IP
                ip_request_count[ip] += 1

                # Count requests per endpoint
                endpoint_request_count[endpoint] += 1

                # Detect failed login attempts
                if status == '401':
                    failed_login_attempts[ip] += 1

    return ip_request_count, endpoint_request_count, failed_login_attempts


def write_to_csv(ip_data, endpoint_data, suspicious_data, output_file):
    """
    Writes the processed data to a CSV file.
    """
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_data.items():
            writer.writerow([ip, count])
        writer.writerow([])

        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        for endpoint, count in endpoint_data.items():
            writer.writerow([endpoint, count])
        writer.writerow([])

        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_data.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])


def main():
    ip_request_count, endpoint_request_count, failed_login_attempts = parse_log_file(LOG_FILE)

    # Sort results
    ip_request_count = dict(sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True))
    endpoint_request_count = dict(sorted(endpoint_request_count.items(), key=lambda x: x[1], reverse=True))
    suspicious_activity = {ip: count for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

    # Display results
    print("IP Requests Count:")
    print("IP Address           Request Count")
    for ip, count in ip_request_count.items():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    most_accessed = max(endpoint_request_count.items(), key=lambda x: x[1])
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count}")

    # Write to CSV
    write_to_csv(ip_request_count, endpoint_request_count, suspicious_activity, CSV_OUTPUT_FILE)
    print(f"\nResults saved to {CSV_OUTPUT_FILE}")
