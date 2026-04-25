"""
utils.py — Core utility functions for the Steganography Application.

Sections:
  1. Encryption  — Fernet symmetric encryption with password-derived key
  2. OTP         — Generate, send, and verify 6-digit one-time passwords
  3. Image       — LSB encode/decode steganography using Pillow
"""

import os
import base64
import random
import logging
from io import BytesIO

from PIL import Image
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.core.mail import send_mail
from django.conf import settings

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1: ENCRYPTION UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

# Fixed salt — in production use a random salt stored per-record
_SALT = b'stego_app_fixed_salt_v1'

# Delimiter marking end of hidden message in pixel data
_DELIMITER = '###END###'


def generate_key_from_password(password: str) -> bytes:
    """
    Derive a 32-byte Fernet key from a user password using PBKDF2-HMAC-SHA256.
    The key is deterministic for the same password, allowing decryption without
    storing the key anywhere.

    Args:
        password: Plain-text password string

    Returns:
        URL-safe base64-encoded 32-byte Fernet key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        iterations=390_000,  # OWASP-recommended minimum for PBKDF2-HMAC-SHA256
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key


def encrypt_message(message: str, password: str) -> str:
    """
    Encrypt a plaintext message using Fernet (AES-128-CBC + HMAC-SHA256).

    Args:
        message:  The secret text to encrypt
        password: Password used to derive the encryption key

    Returns:
        Base64-encoded encrypted string
    """
    key = generate_key_from_password(password)
    f = Fernet(key)
    encrypted_bytes = f.encrypt(message.encode('utf-8'))
    return encrypted_bytes.decode('utf-8')


def decrypt_message(encrypted_message: str, password: str) -> str:
    """
    Decrypt a Fernet-encrypted message.

    Args:
        encrypted_message: The encrypted string (from encrypt_message)
        password:          Password used during encryption

    Returns:
        Original plaintext message

    Raises:
        ValueError: If password is wrong or data is corrupted
    """
    try:
        key = generate_key_from_password(password)
        f = Fernet(key)
        decrypted_bytes = f.decrypt(encrypted_message.encode('utf-8'))
        return decrypted_bytes.decode('utf-8')
    except (InvalidToken, Exception) as e:
        logger.error(f"Decryption failed: {e}")
        raise ValueError("Decryption failed — wrong password or corrupted data.")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2: OTP UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def generate_otp() -> str:
    """
    Generate a cryptographically secure 6-digit OTP.

    Returns:
        Zero-padded 6-digit string e.g. '042831'
    """
    return f"{random.SystemRandom().randint(0, 999999):06d}"


def send_otp_email(user_email: str, otp: str, username: str = '') -> bool:
    """
    Send an OTP via email.

    In development (console backend), the OTP prints to the terminal.
    In production, configure SMTP settings in settings.py.

    Args:
        user_email: Recipient email address
        otp:        6-digit OTP string
        username:   Optional username for personalisation

    Returns:
        True on success, False on failure
    """
    subject = '🔐 Your Steganography Decode OTP'
    message = f"""
Hello {username or 'User'},

Your One-Time Password (OTP) for decoding your hidden message is:

    ┌─────────────┐
    │  {otp}  │
    └─────────────┘

This OTP is valid for {getattr(settings, 'OTP_EXPIRY_MINUTES', 5)} minutes.

If you did not request this, please ignore this email.

— Secure Steganography App
"""
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            fail_silently=False,
        )
        logger.info(f"OTP email sent to {user_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email to {user_email}: {e}")
        return False


def verify_otp(input_otp: str, stored_otp: str) -> bool:
    """
    Compare user-entered OTP with stored OTP (constant-time comparison).

    Args:
        input_otp:  OTP entered by user
        stored_otp: OTP stored in database

    Returns:
        True if they match exactly
    """
    import hmac
    return hmac.compare_digest(
        input_otp.strip(),
        stored_otp.strip()
    )


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3: IMAGE STEGANOGRAPHY UTILITIES (LSB)
# ─────────────────────────────────────────────────────────────────────────────

def get_image_capacity(image: Image.Image) -> int:
    """
    Calculate maximum bytes that can be hidden in an image.
    Formula: (width × height × 3 channels) // 8 bits per byte

    Args:
        image: PIL Image object

    Returns:
        Maximum message size in bytes
    """
    w, h = image.size
    return (w * h * 3) // 8


# Pre-compute delimiter as UTF-8 bytes and its bit representation
_DELIMITER_BYTES = _DELIMITER.encode('utf-8')


def _data_to_bits(data: bytes) -> list:
    """
    Convert raw bytes to a flat list of bits (MSB-first per byte).
    Works correctly with all Unicode / multibyte UTF-8 characters.
    """
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list) -> bytes:
    """Convert a flat list of bits back to a bytes object."""
    result = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i + 8]
        if len(byte_bits) < 8:
            break
        byte = 0
        for bit in byte_bits:
            byte = (byte << 1) | bit
        result.append(byte)
    return bytes(result)


def _get_pixels(img: Image.Image) -> list:
    """Compatibility wrapper: use get_flattened_data() when available (Pillow ≥14)."""
    if hasattr(img, 'get_flattened_data'):
        return list(img.get_flattened_data())
    return list(img.getdata())  # type: ignore[arg-type]


def encode_image(image_file, encrypted_message: str) -> BytesIO:
    """
    Hide an encrypted message inside an image using LSB steganography.

    Process:
      1. Convert image to RGB (always PNG for lossless output)
      2. Encode message as UTF-8 bytes + delimiter bytes
      3. Convert bytes to bit stream
      4. Overwrite LSB of R, G, B channels sequentially
      5. Return encoded image as BytesIO PNG

    Args:
        image_file:        File-like object or path to source image
        encrypted_message: Encrypted string to embed

    Returns:
        BytesIO containing the encoded PNG image

    Raises:
        ValueError: If message is too large for the image
    """
    img = Image.open(image_file).convert('RGB')

    # Encode payload as UTF-8 bytes (handles all Unicode / emoji / CJK etc.)
    payload_bytes = encrypted_message.encode('utf-8') + _DELIMITER_BYTES
    payload_bits  = _data_to_bits(payload_bytes)

    # Capacity check
    capacity_bytes = get_image_capacity(img)
    if len(payload_bits) > capacity_bytes * 8:
        raise ValueError(
            f"Message too large. "
            f"Max capacity: {capacity_bytes} bytes, "
            f"your message needs {(len(payload_bits) + 7) // 8} bytes."
        )

    pixels = _get_pixels(img)
    bit_index = 0
    new_pixels = []

    for pixel in pixels:
        r, g, b = pixel
        new_channels = []
        for ch in [r, g, b]:
            if bit_index < len(payload_bits):
                # Replace the Least Significant Bit with our message bit
                ch = (ch & 0xFE) | payload_bits[bit_index]
                bit_index += 1
            new_channels.append(ch)
        new_pixels.append(tuple(new_channels))

    # Build the new image and save as lossless PNG
    encoded_img = Image.new('RGB', img.size)
    encoded_img.putdata(new_pixels)

    output = BytesIO()
    encoded_img.save(output, format='PNG', optimize=False)
    output.seek(0)

    logger.info(f"Encoded {len(payload_bits)} bits into {img.size} image")
    return output


def decode_image(image_file) -> str:
    """
    Extract a hidden message from an LSB-encoded image.

    Process:
      1. Open image and read RGB channels
      2. Collect LSB from each channel sequentially into a bit stream
      3. Reconstruct bytes from bits
      4. Search for delimiter bytes, decode UTF-8 payload

    Args:
        image_file: File-like object or path to encoded image

    Returns:
        Encrypted message string (to be decrypted separately)

    Raises:
        ValueError: If no valid hidden message is found
    """
    img = Image.open(image_file).convert('RGB')
    pixels = _get_pixels(img)

    bits = []
    for pixel in pixels:
        for channel in pixel:   # R, G, B
            bits.append(channel & 1)

    raw_bytes = _bits_to_bytes(bits)

    delimiter_pos = raw_bytes.find(_DELIMITER_BYTES)
    if delimiter_pos == -1:
        raise ValueError(
            "No hidden message found in this image. "
            "Ensure the image was encoded by this application."
        )

    hidden_payload = raw_bytes[:delimiter_pos].decode('utf-8')
    logger.info(f"Decoded {len(hidden_payload)} characters from image")
    return hidden_payload
