#!/usr/bin/env python3
"""
Email sending module for knock_knock security scanner.

Handles SMTP email delivery with HTML reports.
"""

import logging
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)


class EmailSender:
    """Handles sending HTML reports via SMTP."""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_use_tls: bool,
        from_address: str,
        to_addresses: List[str],
        subject_prefix: str
    ):
        """
        Initialize email sender with SMTP configuration.

        Args:
            smtp_host: SMTP server hostname
            smtp_port: SMTP server port
            smtp_use_tls: Whether to use TLS
            from_address: Email 'From' address
            to_addresses: List of recipient email addresses
            subject_prefix: Subject line prefix
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_use_tls = smtp_use_tls
        self.from_address = from_address
        self.to_addresses = to_addresses
        self.subject_prefix = subject_prefix

    def send_report(
        self,
        html_content: str,
        html_file_path: Path
    ) -> bool:
        """
        Send HTML report via email.

        The HTML is both embedded in the email body and attached as a file.

        Args:
            html_content: HTML report content as string
            html_file_path: Path to HTML file to attach

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            # Create message
            msg = MIMEMultipart('mixed')
            msg['From'] = self.from_address
            msg['To'] = ', '.join(self.to_addresses)

            # Subject with date
            today = datetime.now().strftime('%Y-%m-%d')
            msg['Subject'] = f"{self.subject_prefix} - {today}"

            # Create multipart/alternative for HTML body
            msg_alternative = MIMEMultipart('alternative')
            msg.attach(msg_alternative)

            # Add plain text version (simplified)
            text_content = self._html_to_text(html_content)
            msg_alternative.attach(MIMEText(text_content, 'plain'))

            # Add HTML version
            msg_alternative.attach(MIMEText(html_content, 'html'))

            # Attach HTML file
            if html_file_path.exists():
                with open(html_file_path, 'rb') as f:
                    attachment = MIMEApplication(f.read(), _subtype='html')
                    attachment.add_header(
                        'Content-Disposition',
                        'attachment',
                        filename=html_file_path.name
                    )
                    msg.attach(attachment)

            # Send email
            logger.info(f"Connecting to SMTP server {self.smtp_host}:{self.smtp_port}")

            if self.smtp_use_tls:
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    server.starttls()
                    server.send_message(msg)
            else:
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    server.send_message(msg)

            logger.info(f"Email sent successfully to {', '.join(self.to_addresses)}")
            return True

        except smtplib.SMTPException as e:
            logger.error(f"SMTP error while sending email: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error while sending email: {e}")
            return False

    def _html_to_text(self, html_content: str) -> str:
        """
        Convert HTML to plain text for email clients that don't support HTML.

        This is a simple implementation that just strips tags.

        Args:
            html_content: HTML string

        Returns:
            Plain text version
        """
        # Simple approach: just provide a message directing to the attachment
        text = f"""
{self.subject_prefix}
{'=' * len(self.subject_prefix)}

This is an HTML report. Please view the HTML version or open the attached file.

Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

If you cannot view HTML emails, please open the attached HTML file in a web browser.
"""
        return text
