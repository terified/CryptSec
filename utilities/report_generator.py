import os
from datetime import datetime

REPORT_DIR = "reports"
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

def generate_report(username, actions):
    report_file = os.path.join(REPORT_DIR, f"{username}_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt")
    with open(report_file, 'w') as file:
        file.write(f"Report for user: {username}\n")
        file.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        file.write("Actions performed:\n")
        for action in actions:
            file.write(f"- {action}\n")
    print(f"Report generated: {report_file}")
    return report_file

# Пример использования
if __name__ == "__main__":
    actions = [
        "User logged in",
        "Encrypted data using AES",
        "Decrypted data using AES",
        "Generated HMAC",
        "Verified HMAC"
    ]
    generate_report("test_user", actions)