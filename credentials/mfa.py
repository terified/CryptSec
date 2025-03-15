import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_otp_via_email(email):
    otp = generate_otp()
    sender_email = "Crypt_Sec_Manager@proton.me"  # Замените на действительный email отправителя
    sender_password = "zRPbq684AGqFdf5"  # Замените на действительный пароль отправителя
    smtp_server = "smtp.protonmail.com"  # Замените на действительный SMTP сервер
    smtp_port = 587  # Стандартный порт для TLS

    subject = "Your OTP Code"
    body = f"Your OTP code is {otp}"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, msg.as_string())
        server.quit()
        return otp
    except smtplib.SMTPException as e:
        print(f"Failed to send OTP: {e}")
        return None

def verify_otp(user_otp, actual_otp):
    return user_otp == actual_otp