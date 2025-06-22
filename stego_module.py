# stego_module.py


from PIL import Image
from cryptography.fernet import Fernet
import base64
import hashlib

### ---------- Helper Functions ---------- ###

def generate_key(password: str) -> bytes:
    """Generate a Fernet key based on the password."""
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

def encrypt_message(message: str, password: str) -> bytes:
    key = generate_key(password)
    f = Fernet(key)
    return f.encrypt(message.encode())

def decrypt_message(encrypted: bytes, password: str) -> str:
    key = generate_key(password)
    f = Fernet(key)
    return f.decrypt(encrypted).decode()

def _int_to_bin(rgb):
    return tuple(format(c, '08b') for c in rgb)

def _bin_to_int(rgb_bin):
    return tuple(int(b, 2) for b in rgb_bin)

def _merge_rgb(rgb_bin, bit):
    r, g, b = rgb_bin
    r = r[:-1] + bit
    return (r, g, b)

### ---------- Core Functions ---------- ###

def hide_message(input_img_path, output_img_path, message, password):
    img = Image.open(input_img_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    encoded = img.copy()
    width, height = img.size

    # Encrypt message and convert to binary
    encrypted = encrypt_message(message, password)
    binary_message = ''.join(format(byte, '08b') for byte in encrypted)
    binary_message += '00000011' * 8  # EOF marker: repeated ETX (0x03)

    data_index = 0
    for y in range(height):
        for x in range(width):
            if data_index < len(binary_message):
                pixel = img.getpixel((x, y))
                rgb_bin = _int_to_bin(pixel)
                new_rgb_bin = _merge_rgb(rgb_bin, binary_message[data_index])
                encoded.putpixel((x, y), _bin_to_int(new_rgb_bin))
                data_index += 1
            else:
                encoded.save(output_img_path)
                print(f"[+] Encrypted message hidden in: {output_img_path}")
                return
    raise ValueError("Message too large to hide in the image.")

def extract_message(stego_img_path, password):
    img = Image.open(stego_img_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    binary_data = ""
    width, height = img.size

    for y in range(height):
        for x in range(width):
            r, g, b = img.getpixel((x, y)) # type: ignore
            binary_data += format(r, '08b')[-1]

    # Read 8-bit chunks
    bytes_list = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    
    # Stop at EOF marker (ETX x8)
    eof_pattern = '00000011' * 8
    full_binary = ''.join(bytes_list)
    eof_index = full_binary.find(eof_pattern)
    if eof_index == -1:
        raise ValueError("EOF marker not found — likely wrong password or corrupt image.")

    trimmed_bin = full_binary[:eof_index]
    encrypted_bytes = bytes(int(trimmed_bin[i:i+8], 2) for i in range(0, len(trimmed_bin), 8))

    try:
        return decrypt_message(encrypted_bytes, password)
    except Exception:
        raise ValueError("Decryption failed. Wrong password or corrupted data.")
