"""
Email service for sending alert notifications.

Uses aiosmtplib for async email sending.
"""

from typing import List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

import aiosmtplib
from loguru import logger

from app.core.config import settings


class EmailService:
    """
    Async email service for sending notifications.

    Supports HTML and plain text emails via SMTP.
    """

    def __init__(self):
        self.host = settings.SMTP_HOST
        self.port = settings.SMTP_PORT
        self.username = settings.SMTP_USER
        self.password = settings.SMTP_PASSWORD
        self.from_email = settings.SMTP_FROM
        self.use_tls = settings.SMTP_TLS

    async def send_email(
        self,
        to: List[str],
        subject: str,
        body_html: str,
        body_text: Optional[str] = None
    ) -> bool:
        """
        Send an email.

        Args:
            to: List of recipient email addresses
            subject: Email subject
            body_html: HTML body content
            body_text: Plain text body (optional)

        Returns:
            True if email sent successfully
        """
        if not self.username or not self.password:
            logger.warning("SMTP credentials not configured, skipping email")
            return False

        try:
            # Create message
            message = MIMEMultipart("alternative")
            message["From"] = self.from_email
            message["To"] = ", ".join(to)
            message["Subject"] = subject

            # Add plain text part
            if body_text:
                part_text = MIMEText(body_text, "plain")
                message.attach(part_text)

            # Add HTML part
            part_html = MIMEText(body_html, "html")
            message.attach(part_html)

            # Send email
            await aiosmtplib.send(
                message,
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                start_tls=self.use_tls
            )

            logger.info(f"Email sent to {to}: {subject}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False

    async def send_alert_notification(
        self,
        to: List[str],
        alert_data: dict
    ) -> bool:
        """
        Send alert notification email.

        Args:
            to: Recipient email addresses
            alert_data: Alert information

        Returns:
            True if sent successfully
        """
        severity = alert_data.get("severity", "unknown").upper()
        title = alert_data.get("title", "Security Alert")
        timestamp = alert_data.get("timestamp", datetime.utcnow().isoformat())

        subject = f"[SentinelFlow] {severity} Alert: {title}"

        # HTML body
        body_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .alert-box {{
                    border: 2px solid #{'dc3545' if severity in ['CRITICAL', 'HIGH'] else '#ffc107'};
                    border-radius: 8px;
                    padding: 20px;
                    margin: 20px 0;
                }}
                .severity-critical {{ color: #dc3545; }}
                .severity-high {{ color: #dc3545; }}
                .severity-medium {{ color: #ffc107; }}
                .severity-low {{ color: #17a2b8; }}
                .field {{ margin: 10px 0; }}
                .label {{ font-weight: bold; color: #666; }}
                .value {{ color: #333; }}
            </style>
        </head>
        <body>
            <h1>SentinelFlow Security Alert</h1>

            <div class="alert-box">
                <h2 class="severity-{severity.lower()}">{severity}: {title}</h2>

                <div class="field">
                    <span class="label">Timestamp:</span>
                    <span class="value">{timestamp}</span>
                </div>

                <div class="field">
                    <span class="label">Source IP:</span>
                    <span class="value">{alert_data.get('src_ip', 'N/A')}</span>
                </div>

                <div class="field">
                    <span class="label">Destination IP:</span>
                    <span class="value">{alert_data.get('dst_ip', 'N/A')}</span>
                </div>

                <div class="field">
                    <span class="label">Attack Category:</span>
                    <span class="value">{alert_data.get('attack_category', 'N/A')}</span>
                </div>

                <div class="field">
                    <span class="label">MITRE ATT&CK:</span>
                    <span class="value">{alert_data.get('mitre_tactic', 'N/A')} - {alert_data.get('mitre_technique', 'N/A')}</span>
                </div>

                <div class="field">
                    <span class="label">Confidence:</span>
                    <span class="value">{alert_data.get('confidence', 0) * 100:.1f}%</span>
                </div>

                <div class="field">
                    <span class="label">Description:</span>
                    <span class="value">{alert_data.get('description', 'No description available')}</span>
                </div>
            </div>

            <p>
                <a href="{settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else 'http://localhost:3000'}/alerts/{alert_data.get('id', '')}">
                    View in Dashboard
                </a>
            </p>

            <hr>
            <p style="color: #666; font-size: 12px;">
                This is an automated alert from SentinelFlow Network Intrusion Detection System.
            </p>
        </body>
        </html>
        """

        # Plain text body
        body_text = f"""
        SentinelFlow Security Alert

        {severity}: {title}

        Timestamp: {timestamp}
        Source IP: {alert_data.get('src_ip', 'N/A')}
        Destination IP: {alert_data.get('dst_ip', 'N/A')}
        Attack Category: {alert_data.get('attack_category', 'N/A')}
        MITRE ATT&CK: {alert_data.get('mitre_tactic', 'N/A')} - {alert_data.get('mitre_technique', 'N/A')}
        Confidence: {alert_data.get('confidence', 0) * 100:.1f}%

        Description: {alert_data.get('description', 'No description available')}

        ---
        This is an automated alert from SentinelFlow Network Intrusion Detection System.
        """

        return await self.send_email(to, subject, body_html, body_text)


# Global email service instance
email_service = EmailService()
