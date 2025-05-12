import smtplib
from email.mime.text import MIMEText
import random
import string
import smtplib
from email.mime.text import MIMEText
import os

def generate_code(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_verification_email(receiver_email, code):
    sender_email = 'compscithesis@gmail.com'  # Match your app config
    sender_password = 'yrrl idjh teci uamk'  # Match your app config
    
    subject = "Your Verification Code"
    body = f"Your verification code is: {code}"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender_email, sender_password)
            smtp.send_message(msg)
    except Exception as e:
        print(f"Failed to send verification email: {e}")