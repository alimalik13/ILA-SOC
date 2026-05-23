import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

def send_soc_notification_email(subject, body, recipient):
    """
    Sends a SOC notification email using SMTP.
    Configured via .env variables.
    """
    try:
        mail_server = os.getenv('MAIL_SERVER')
        mail_port = int(os.getenv('MAIL_PORT', 587))
        mail_username = os.getenv('MAIL_USERNAME')
        mail_password = os.getenv('MAIL_PASSWORD')
        mail_use_tls = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'

        if not mail_server or not mail_username or not mail_password:
            print(f"[WARNING] SMTP configuration missing. Cannot send email to {recipient}")
            return False

        msg = MIMEMultipart()
        msg['From'] = mail_username
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(mail_server, mail_port) as server:
            if mail_use_tls:
                server.starttls()
            
            server.login(mail_username, mail_password)
            server.send_message(msg)
            print(f"[INFO] SOC notification email sent successfully to {recipient}")
            return True
    except Exception as e:
        print(f"[ERROR] Failed to send SOC notification email: {str(e)}")
        return False
