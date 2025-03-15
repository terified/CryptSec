import qrcode
from PIL import Image
import io

# Генерация QR-кода
def generate_qr_code(data, file_path="qrcode.png"):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill="black", back_color="white")
    img.save(file_path)

# Чтение данных из QR-кода
def read_qr_code(file_path):
    from pyzbar.pyzbar import decode

    img = Image.open(file_path)
    result = decode(img)
    if result:
        return result[0].data.decode("utf-8")
    return None