# core/quishing_parser.py
from PIL import Image
from pyzbar.pyzbar import decode
import io

def scan_image_for_qr(image_bytes: bytes) -> list:
    """
    Scans raw image bytes for QR codes and extracts decoded URLs/text.
    """
    detected_payloads = []
    try:
        image = Image.open(io.BytesIO(image_bytes))
        decoded_objects = decode(image)
        for obj in decoded_objects:
            if obj.type == 'QRCODE':
                detected_payloads.append(obj.data.decode('utf-8'))
    except Exception as e:
        # If image format is unsupported or corrupted
        pass
    return detected_payloads