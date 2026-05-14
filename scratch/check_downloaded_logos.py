from PIL import Image

try:
    img = Image.open(r"c:\Users\asm_t\Downloads\reconx_logo-removebg-preview.png")
    print(f"Removed BG Logo: size={img.size}, mode={img.mode}")
except Exception as e:
    print(f"Error: {e}")

try:
    img2 = Image.open(r"c:\Users\asm_t\Downloads\reconx_logo.png")
    print(f"Original Logo: size={img2.size}, mode={img2.mode}")
except Exception as e:
    print(f"Error: {e}")
