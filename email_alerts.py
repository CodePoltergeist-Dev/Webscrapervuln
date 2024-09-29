import smtplib
from email.mime.text import MIMEText

# Sample vulnerability data based on your provided structure
vulnerability_data = {
    "id": "CVE-1999-0095",
    "sourceIdentifier": "cve@mitre.org",
    "published": "1988-10-01T04:00:00.000",
    "lastModified": "2019-06-11T20:29:00.263",
    "vulnStatus": "Modified",
    "descriptions": [
        {
            "lang": "en",
            "value": "The debug command in Sendmail allows remote attackers to execute commands as root."
        }
    ],
    "metrics": {
        "cvssMetricV2": {
            "baseScore": 10,
            "baseSeverity": "HIGH"
        }
    },
    "references": [
        "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0095",
        "https://nvd.nist.gov/vuln/detail/CVE-1999-0095"
    ]
}

# Function to send email alert
def send_email_alert(vulnerability):
    smtp_server = "smtp.gmail.com"
    port = 587  # For starttls
    sender_email = "sriharan337@gmail.com"  # Replace with your email
    password = "pqgo knqc rpjo suqj "  # Use an app password or environment variable
    recipient_email = "sriharanmahimala125@gmail.com"  # Your recipient email
    
    # Craft the email content
    message = f"""
    Subject: Vulnerability Alert: {vulnerability['id']}

    Vulnerability ID: {vulnerability['id']}
    Source Identifier: {vulnerability['sourceIdentifier']}
    Published Date: {vulnerability['published']}
    Last Modified: {vulnerability['lastModified']}
    Status: {vulnerability['vulnStatus']}
    
    Description: {vulnerability['descriptions'][0]['value']}
    
    CVSS Score: {vulnerability['metrics']['cvssMetricV2']['baseScore']}
    Base Severity: {vulnerability['metrics']['cvssMetricV2']['baseSeverity']}
    
    References:
    - {vulnerability['references'][0]}
    - {vulnerability['references'][1]}
    """

    # Send the email
    try:
        server = smtplib.SMTP(smtp_server, port)
        server.starttls()
        server.login(sender_email, password)

        msg = MIMEText(message)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        print("Email sent successfully!")
    except Exception as e:
        print(f"Error sending email: {e}")
    finally:
        server.quit()

# Example usage
if __name__ == "__main__":
    send_email_alert(vulnerability_data)

