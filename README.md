# 🔐 StegoCrypt — Secure Image Steganography Web Application

A production-ready Django web application that hides encrypted messages inside images using **LSB Steganography**, **Fernet Encryption (AES-128-CBC)**, and **OTP-based Two-Factor Authentication**.

---

## ✨ Features

| Feature | Details |
|---|---|
| **LSB Steganography** | Hides encrypted data in image pixel LSBs — visually identical to original |
| **Fernet Encryption** | AES-128-CBC + HMAC-SHA256, key derived from password via PBKDF2 (390k iterations) |
| **OTP 2FA** | 6-digit time-limited OTP sent to email before any decode |
| **Capacity Check** | Real-time AJAX check prevents message overflow |
| **Shareable Links** | UUID-based decode URLs — `/decode/<uuid>/` |
| **User Dashboard** | All encoded images with thumbnails, timestamps, download links |
| **JPG → PNG auto-convert** | All images stored losslessly to protect LSB data |
| **UTF-8 Support** | Handles emoji, CJK, accented characters in messages |

---

## 📁 Project Structure

```
steganography_project/
├── manage.py
├── requirements.txt
├── README.md
│
├── steganography_project/          # Django project config
│   ├── __init__.py
│   ├── settings.py                 # All settings (email, OTP expiry, media)
│   ├── urls.py                     # Root URL dispatcher
│   └── wsgi.py
│
├── steganography_app/              # Main application
│   ├── __init__.py
│   ├── apps.py
│   ├── admin.py                    # Admin panel registrations
│   ├── models.py                   # EncodedImage + OTPRecord models
│   ├── forms.py                    # All forms (signup, encode, decode, OTP)
│   ├── views.py                    # All views with full encode/decode flow
│   ├── urls.py                     # App-level URL patterns
│   ├── utils.py                    # Core logic: LSB, Fernet, OTP
│   │
│   └── templates/steganography_app/
│       ├── base.html               # Dark cipher-themed base layout
│       ├── home.html               # Landing page
│       ├── login.html
│       ├── signup.html
│       ├── dashboard.html          # Image history + shareable links
│       ├── encode.html             # Encode form with live capacity meter
│       ├── decode.html             # Decode step 1 (upload + password)
│       ├── decode_link.html        # Decode via shareable UUID link
│       ├── otp_verify.html         # OTP entry with 5-min countdown
│       └── decode_result.html      # Revealed message display
│
└── media/                          # User-uploaded & encoded images
    ├── original_images/
    └── encoded_images/
```

---

## 🚀 STEP 1: Setup & Installation

### 1.1 Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate          # Linux/Mac
# venv\Scripts\activate           # Windows
```

### 1.2 Install dependencies

```bash
pip install -r requirements.txt
```

**requirements.txt:**
```
Django>=4.2,<5.0
Pillow>=10.0.0
cryptography>=41.0.0
```

### 1.3 Apply database migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### 1.4 Create a superuser (optional, for admin panel)

```bash
python manage.py createsuperuser
```

### 1.5 Run the development server

```bash
python manage.py runserver
```

Open: **http://127.0.0.1:8000/**

---

## 📧 STEP 2: Email / OTP Configuration

### Development (default — OTP printed to terminal)

In `settings.py`, the default backend is:
```python
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
```
When you trigger a decode, **look at the terminal** — the OTP appears there.

### Production (Gmail SMTP example)

Edit `settings.py`:
```python
EMAIL_BACKEND    = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST       = 'smtp.gmail.com'
EMAIL_PORT       = 587
EMAIL_USE_TLS    = True
EMAIL_HOST_USER  = 'your@gmail.com'          # or use os.environ.get(...)
EMAIL_HOST_PASSWORD = 'your-app-password'    # Gmail App Password (not login password)
DEFAULT_FROM_EMAIL = 'your@gmail.com'
```

> **Gmail note:** Enable 2FA on your Google account → create an **App Password** (not your normal password).

---

## 🔄 How Each Flow Works

### Encode Flow

```
User uploads image
      ↓
Enter secret message + password + optional label
      ↓
[Server] encrypt_message(message, password) → Fernet ciphertext
      ↓
[Server] encode_image(image, ciphertext)
         → payload bytes = ciphertext.encode('utf-8') + b'###END###'
         → convert to bit stream
         → replace LSB of each R,G,B channel pixel by pixel
         → save as lossless PNG
      ↓
Record saved to DB (EncodedImage model) with UUID
      ↓
User downloads PNG from Dashboard
```

### Decode Flow (2FA)

```
User uploads encoded PNG + enters password
      ↓
[Server] generate_otp() → 6-digit code
         save OTPRecord to DB (expires in 5 min)
         send_otp_email() → console (dev) or SMTP (prod)
      ↓
User enters OTP on verification page
      ↓
[Server] check: not expired + verify_otp(input, stored)
      ↓
[Server] decode_image(png) → extract ciphertext from LSBs
         decrypt_message(ciphertext, password) → original plaintext
      ↓
Message displayed to user
```

---

## 🔐 Security Architecture

### Encryption
- **Algorithm:** Fernet = AES-128-CBC + HMAC-SHA256
- **Key derivation:** PBKDF2-HMAC-SHA256, 390,000 iterations (OWASP minimum), fixed salt
- **Result:** Without the exact password, decryption produces garbage or raises `InvalidToken`

### LSB Steganography
- The **Least Significant Bit** of each R, G, B channel is replaced with one bit of the payload
- Visual change per channel: max ±1 intensity (imperceptible to human eye)
- All images saved as **PNG** (lossless) — JPEG compression would destroy LSB data
- Delimiter `###END###` marks end of payload; works with full UTF-8 (emoji, CJK, etc.)

### OTP Two-Factor Authentication
- `random.SystemRandom()` uses OS-level entropy (cryptographically secure)
- Stored in `OTPRecord` DB table (not just session)
- Expires in **5 minutes** (configurable via `OTP_EXPIRY_MINUTES` in settings)
- Verified with `hmac.compare_digest()` (constant-time, prevents timing attacks)
- Old unverified OTPs are deleted before generating a new one

### Capacity Formula
```
max_bytes = (image_width × image_height × 3) // 8
```
A 800×600 image → 180,000 bytes capacity (~175 KB of message).

---

## 🌐 URL Reference

| URL | View | Auth Required |
|---|---|---|
| `/` | Home / landing | No |
| `/signup/` | User registration | No |
| `/login/` | Login | No |
| `/logout/` | Logout | No |
| `/dashboard/` | Image history | ✅ Yes |
| `/encode/` | Encode message | ✅ Yes |
| `/decode/` | Decode (upload) | ✅ Yes |
| `/decode/<uuid>/` | Decode via link | ✅ Yes |
| `/decode/verify-otp/` | OTP verification | ✅ Yes |
| `/decode/resend-otp/` | Resend OTP | ✅ Yes |
| `/api/capacity-check/` | AJAX capacity check | ✅ Yes |
| `/admin/` | Django admin | ✅ Superuser |

---

## ☁️ Production Deployment Guide

### Option A: Render (free tier)

1. Push to GitHub
2. Create a new **Web Service** on render.com
3. Set build command: `pip install -r requirements.txt && python manage.py migrate`
4. Set start command: `gunicorn steganography_project.wsgi`
5. Add environment variables: `SECRET_KEY`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`

### Option B: AWS EC2 + Nginx + Gunicorn

```bash
pip install gunicorn
gunicorn steganography_project.wsgi:application --bind 0.0.0.0:8000
```

### S3 Media Storage (django-storages)

```bash
pip install boto3 django-storages
```

Add to `settings.py`:
```python
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
AWS_STORAGE_BUCKET_NAME = 'your-bucket'
AWS_S3_REGION_NAME = 'us-east-1'
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
```

### Redis for OTP/Sessions (production)

```bash
pip install django-redis
```

```python
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
    }
}
SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"
```

### Production Security Checklist

```python
DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com']
SECRET_KEY = os.environ.get('SECRET_KEY')           # Never hardcode!
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
```

---

## 🧪 Quick Smoke Test (without browser)

```bash
# 1. Start server
python manage.py runserver

# 2. Register at http://127.0.0.1:8000/signup/

# 3. Encode a message:
#    - Go to /encode/
#    - Upload any image
#    - Type a message
#    - Set a password (e.g. "test123")
#    - Click Encode

# 4. Decode the message:
#    - Go to /decode/ or click the image in dashboard
#    - Upload the downloaded PNG
#    - Enter the same password
#    - CHECK THE TERMINAL for the OTP code
#    - Enter OTP → see original message
```

---

## 📚 Technical References

- **Fernet Spec:** https://github.com/fernet/spec/
- **PBKDF2 OWASP:** https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- **LSB Steganography:** Least Significant Bit substitution in spatial domain
- **Django Auth:** https://docs.djangoproject.com/en/4.2/topics/auth/
