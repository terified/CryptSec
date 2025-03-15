import os

def hide_data_in_image(image_path, data):
    with open(image_path, "ab") as img:
        img.write(data)

def extract_data_from_image(image_path):
    with open(image_path, "rb") as img:
        img.seek(-1024, os.SEEK_END)
        return img.read(1024)