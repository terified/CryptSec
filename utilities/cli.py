import argparse
import getpass
from utilities.module_loader import load_all_modules_from_directory
from credentials.user_auth import register_user, login_user
from credentials.password_manager import add_password, get_password
from credentials.mfa import send_otp_via_email, verify_otp
from utilities.config_encrypt import encrypt_config, decrypt_config
from utilities.logging import log_info, log_warning, log_error
from utilities.report_generator import generate_report

# Load all encryption modules
encryption_modules = load_all_modules_from_directory("cryptography")

def main():
    parser = argparse.ArgumentParser(description="Encryption Tool CLI")
    parser.add_argument("action", choices=[
        "register", "login", "encrypt", "decrypt", "generate-hmac", "verify-hmac",
        "hash-password", "add-password", "get-password", "encrypt-config", "decrypt-config",
        "generate-report"
    ], help="Action to perform")
    parser.add_argument("--username", help="Username for registration or login")
    parser.add_argument("--password", help="Password for registration or login")
    parser.add_argument("--email", help="Email for registration")
    parser.add_argument("--data", help="Data to encrypt or decrypt")
    parser.add_argument("--key", help="Key for encryption or decryption")
    parser.add_argument("--account", help="Account name for password management")
    parser.add_argument("--config-file", help="Path to the configuration file")
    parser.add_argument("--key-file", help="Path to the key file")

    args = parser.parse_args()
    current_user = None

    try:
        if args.action == "register":
            if args.username and args.password and args.email:
                if register_user(args.username, args.password):
                    otp = send_otp_via_email(args.email)
                    user_otp = input("Enter the OTP sent to your email: ")
                    if verify_otp(user_otp, otp):
                        log_info(f"User '{args.username}' registered successfully.")
                    else:
                        log_warning(f"Failed registration attempt for user '{args.username}' due to invalid OTP.")
            else:
                print("Username, password, and email are required for registration.")
        
        elif args.action == "login":
            if args.username and args.password:
                if login_user(args.username, args.password):
                    email = input("Enter your registered email: ")
                    otp = send_otp_via_email(email)
                    user_otp = input("Enter the OTP sent to your email: ")
                    if verify_otp(user_otp, otp):
                        current_user = args.username
                        log_info(f"User '{args.username}' logged in successfully.")
                    else:
                        log_warning(f"Failed login attempt for user '{args.username}' due to invalid OTP.")
            else:
                print("Username and password are required for login.")
        
        elif current_user:
            if args.action == "encrypt":
                if args.data and args.key:
                    encrypted_data = encryption_modules['aes_encrypt'].aes_encrypt(args.data.encode(), args.key)
                    print("Encrypted data:", encrypted_data)
                    log_info(f"User '{current_user}' encrypted data using AES.")
                else:
                    print("Data and key are required for encryption.")
            
            elif args.action == "decrypt":
                if args.data and args.key:
                    decrypted_data = encryption_modules['aes_encrypt'].aes_decrypt(args.data.encode(), args.key)
                    print("Decrypted data:", decrypted_data)
                    log_info(f"User '{current_user}' decrypted data using AES.")
                else:
                    print("Data and key are required for decryption.")
            
            elif args.action == "generate-hmac":
                if args.data and args.key:
                    hmac_value = encryption_modules['hmac_integrity'].generate_hmac(args.data.encode(), args.key.encode())
                    print("Generated HMAC:", hmac_value)
                    log_info(f"User '{current_user}' generated HMAC.")
                else:
                    print("Data and key are required for HMAC generation.")
            
            elif args.action == "verify-hmac":
                if args.data and args.key:
                    hmac_value = input("Enter HMAC value: ").encode()
                    if encryption_modules['hmac_integrity'].verify_integrity(args.data.encode(), args.key.encode(), hmac_value):
                        print("HMAC verified successfully.")
                        log_info(f"User '{current_user}' verified HMAC.")
                    else:
                        print("Failed to verify HMAC.")
                        log_warning(f"User '{current_user}' failed to verify HMAC.")
                else:
                    print("Data and key are required for HMAC verification.")
            
            elif args.action == "hash-password":
                if args.password:
                    salt = os.urandom(16)
                    hashed_password = encryption_modules['password_hash'].hash_password(args.password, salt)
                    print("Hashed password:", hashed_password)
                    log_info(f"User '{current_user}' hashed password.")
                else:
                    print("Password is required for hashing.")
            
            elif args.action == "add-password":
                if args.account and args.password:
                    add_password(current_user, args.account, args.password)
                    log_info(f"User '{current_user}' added password for account '{args.account}'.")
                else:
                    print("Account and password are required for adding a password.")
            
            elif args.action == "get-password":
                if args.account:
                    password = get_password(current_user, args.account)
                    print(f"Password for account '{args.account}': {password}")
                    log_info(f"User '{current_user}' retrieved password for account '{args.account}'.")
                else:
                    print("Account is required for retrieving a password.")
            
            elif args.action == "encrypt-config":
                if args.config_file and args.key_file:
                    encrypt_config(args.config_file, args.key_file)
                    log_info(f"User '{current_user}' encrypted configuration file '{args.config_file}'.")
                else:
                    print("Config file and key file are required for encryption.")
            
            elif args.action == "decrypt-config":
                if args.config_file and args.key_file:
                    decrypt_config(args.config_file, args.key_file)
                    log_info(f"User '{current_user}' decrypted configuration file '{args.config_file}'.")
                else:
                    print("Config file and key file are required for decryption.")
            
            elif args.action == "generate-report":
                report_file = generate_report(current_user, user_actions)
                log_info(f"User '{current_user}' generated report: {report_file}")
        
        else:
            print("Please login or register first.")
    
    except Exception as e:
        print(f"An error occurred: {e}")
        log_error(f"An error occurred for user '{current_user}': {e}")

if __name__ == "__main__":
    main()