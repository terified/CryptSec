import hashlib
from database import add_user, get_user
from utilities.otp import send_otp_via_email, verify_otp, generate_otp
from utilities.encryption import encrypt_text, decrypt_text

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password, email):
    user = get_user(username)
    if user:
        print("Username already exists.")
        return False
    hashed_password = hash_password(password)
    encrypted_password = encrypt_text(hashed_password)  # Шифрование пароля
    add_user(username, encrypted_password, email)
    otp = generate_otp()  # Генерация OTP
    send_otp_via_email(otp, email)  # Отправка OTP на email
    user_otp = input("Enter the OTP sent to your email: ")
    if verify_otp(user_otp, otp):
        print("Registration successful.")
        return True
    else:
        print("Invalid OTP. Registration failed.")
    return False

def login_user(username, password):
    user = get_user(username)
    if user and user[2] == decrypt_text(hash_password(password)):  # Дешифрование пароля
        print("Login successful.")
        return True
    print("Invalid username or password.")
    return False