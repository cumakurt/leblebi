"""Email sending module for Leblebi"""

import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path


class EmailSender:
    """Send email reports via SMTP"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize email sender with configuration"""
        self.smtp_server = config.get('smtp_server', 'localhost')
        self.smtp_port = config.get('smtp_port', 25)
        self.smtp_use_tls = config.get('smtp_use_tls', False)
        self.smtp_auth_user = config.get('smtp_auth_user', '')
        self.smtp_auth_pass = config.get('smtp_auth_pass', '')
        self.mail_from = config.get('mail_from', 'leblebi@localhost')
        # Support multiple email addresses (comma or semicolon separated)
        mail_to_raw = config.get('mail_to', '')
        if isinstance(mail_to_raw, list):
            self.mail_to = mail_to_raw
        else:
            # Split by comma or semicolon and strip whitespace
            self.mail_to = [addr.strip() for addr in mail_to_raw.replace(';', ',').split(',') if addr.strip()]
        self.mail_subject_prefix = config.get('mail_subject_prefix', 'Leblebi Security Report')
        self.mail_format = config.get('mail_format', 'html_attachment')  # HTML in body + HTML as attachment
    
    def send_report(self, report_file: str) -> bool:
        """Send HTML report as inline email body and as attachment to all recipients"""
        if not self.mail_to or len(self.mail_to) == 0:
            raise ValueError("mail_to is not configured")
        
        if not os.path.exists(report_file):
            raise FileNotFoundError(f"Report file not found: {report_file}")
        
        file_size = os.path.getsize(report_file)
        if file_size == 0:
            raise ValueError("Report file is empty")
        
        # Send HTML in body and as attachment to all recipients
        return self._send_html_with_attachment(report_file)
    
    def _send_html_with_attachment(self, html_file: str) -> bool:
        """Send email with HTML report in body (viewable) and as attachment to all recipients"""
        # Read HTML content
        with open(html_file, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Create multipart message (mixed to support both body and attachment)
        msg = MIMEMultipart('mixed')
        msg['Subject'] = f"{self.mail_subject_prefix} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        msg['From'] = self.mail_from
        # Join multiple recipients with comma for display in email header
        msg['To'] = ', '.join(self.mail_to)
        
        # Create alternative part for email body (text + HTML)
        alt_part = MIMEMultipart('alternative')
        
        # Add plain text alternative
        text_body = (
            "Leblebi Security Report\n\n"
            "This email contains the security report in HTML format.\n"
            "The report is displayed in this email and also attached as an HTML file.\n"
            "\n"
            "Leblebi - Wazuh Security Reports Generator\n"
        )
        alt_part.attach(MIMEText(text_body, 'plain'))
        
        # Add HTML body (will be displayed inline in email)
        alt_part.attach(MIMEText(html_content, 'html', 'utf-8'))
        
        # Attach the alternative part to main message
        msg.attach(alt_part)
        
        # Attach HTML file with original filename (preserves timestamp if present)
        attachment = MIMEText(html_content, 'html', 'utf-8')
        # Extract filename from report file path to preserve timestamp
        report_filename = os.path.basename(html_file)
        attachment.add_header(
            'Content-Disposition',
            'attachment',
            filename=report_filename
        )
        msg.attach(attachment)
        
        return self._send_email(msg)
    
    def _send_email(self, msg) -> bool:
        """Send email via SMTP to all recipients (accepts MIMEMultipart, MIMEText, or Message)"""
        try:
            if self.smtp_use_tls:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            
            # Authentication if provided
            if self.smtp_auth_user and self.smtp_auth_pass:
                server.login(self.smtp_auth_user, self.smtp_auth_pass)
            
            # Send to all recipients (list format for sendmail)
            server.sendmail(self.mail_from, self.mail_to, msg.as_string())
            server.quit()
            
            return True
        except smtplib.SMTPException as e:
            raise RuntimeError(f"SMTP error: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Email sending error: {str(e)}")

