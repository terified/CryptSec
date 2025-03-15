import random
import smtplib
from email.mime.text import MIMEText
import pyotp
import socks
import socket

# Конфигурация SMTP и прокси
SENDER_EMAIL = "Crypt_Sec_Manager@proton.me"
SENDER_PASSWORD = "zRPbq684AGqFdf5"
SMTP_SERVER = "smtp.protonmail.com"
SMTP_PORT = 587
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 60009

def generate_otp(length=6):
    digits = "0123456789"
    otp = "".join(random.choice(digits) for _ in range(length))
    return otp

def send_otp_via_email(otp, recipient_email):
    msg = MIMEText(f"Your OTP is: {otp}")
    msg['Subject'] = "Your OTP Code"
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient_email

    # Настройка прокси-сервера
    socks.set_default_proxy(socks.HTTP, PROXY_HOST, PROXY_PORT)
    socket.socket = socks.socksocket

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

def verify_otp(user_input_otp, actual_otp):
    return user_input_otp == actual_otp

def generate_totp(secret=None):
    if secret is None:
        secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    return totp.now(), secret

def validate_totp(token, secret):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)