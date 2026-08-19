import io
import os
import qrcode
from email.message import EmailMessage

def create_sample_quishing_email(output_path="samples/test_quishing.eml"):
    os.makedirs("samples", exist_ok=True)
    
    qr = qrcode.QRCode(box_size=5, border=2)
    qr.add_data("[https://paypal-account-verification-login-portal.badsite.ru/login](https://paypal-account-verification-login-portal.badsite.ru/login)")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_bytes = img_byte_arr.getvalue()

    msg = EmailMessage()
    msg['Subject'] = 'URGENT: Unauthorized login detected on your PayPal Account'
    msg['From'] = 'security-alert@paypal.com'
    msg['To'] = 'victim-employee@target-corp.com'
    msg['Date'] = 'Wed, 19 Aug 2026 10:15:00 +0000'
    msg['Message-ID'] = '<fake-uuid-987213@bad-relay.ru>'
    
    msg['Received'] = 'from mail.bad-relay.ru ([185.220.101.5]) by mx.target-corp.com with ESMTP; Wed, 19 Aug 2026 10:15:00 +0000'
    msg['Received-SPF'] = 'fail (mx.target-corp.com: domain of paypal.com does not designate 185.220.101.5 as permitted sender)'
    msg['Authentication-Results'] = 'mx.target-corp.com; dkim=fail; spf=fail; dmarc=fail action=none header.from=paypal.com'

    body_text = """Your PayPal account has been temporarily restricted due to suspicious activities.
Please scan the attached QR code with your mobile camera to verify your identity and restore account privileges immediately."""
    
    msg.set_content(body_text)
    msg.add_attachment(img_bytes, maintype='image', subtype='png', filename='Verification_QRCode.png')

    with open(output_path, 'wb') as f:
        f.write(msg.as_bytes())
    
    print(f"[+] Successfully generated test sample at: {output_path}")

if __name__ == "__main__":
    create_sample_quishing_email()
