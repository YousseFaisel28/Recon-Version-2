from PIL import Image
import os

img_path = r"c:\Users\asm_t\Desktop\Recon-Version-2\static\assets\images\logo.png"
if os.path.exists(img_path):
    with Image.open(img_path) as img:
        print(f"Dimensions: {img.size}")
        print(f"Format: {img.format}")
        print(f"Mode: {img.mode}")
else:
    print("File not found")
