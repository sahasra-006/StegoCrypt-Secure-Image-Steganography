"""
views.py — All views for the Steganography Application.

Views:
  home_view          : Landing page
  signup_view        : User registration
  dashboard_view     : User's encoded image history
  encode_view        : Encode message into image
  decode_view        : Multi-step: upload image → OTP → reveal message
  decode_link_view   : Shareable decode link (pre-loads image from DB)
  otp_verify_view    : OTP verification step
  resend_otp_view    : Resend OTP (rate-limited by session flag)
"""

import logging
from io import BytesIO
from PIL import Image

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.core.files.base import ContentFile
from django.utils import timezone
from django.http import Http404

from .forms import UserSignupForm, EncodeForm, DecodeInitForm, OTPVerificationForm
from .models import EncodedImage, OTPRecord
from .utils import (
    encrypt_message, decrypt_message,
    encode_image, decode_image, get_image_capacity,
    generate_otp, send_otp_email, verify_otp
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# HOME
# ─────────────────────────────────────────────────────────────────────────────

def home_view(request):
    """Landing page — redirects authenticated users to dashboard."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'steganography_app/home.html')


# ─────────────────────────────────────────────────────────────────────────────
# AUTHENTICATION
# ─────────────────────────────────────────────────────────────────────────────

def signup_view(request):
    """User registration. Email is mandatory (used for OTP delivery)."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    form = UserSignupForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.save()
        login(request, user)
        messages.success(request, f'Welcome, {user.username}! Your account has been created.')
        return redirect('dashboard')

    return render(request, 'steganography_app/signup.html', {'form': form})


def login_view(request):
    """Standard login using Django's AuthenticationForm."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    form = AuthenticationForm(request, data=request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.get_user()
        login(request, user)
        messages.success(request, f'Welcome back, {user.username}!')
        return redirect(request.GET.get('next', 'dashboard'))

    return render(request, 'steganography_app/login.html', {'form': form})


def logout_view(request):
    """Logout and clear session."""
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('home')


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def dashboard_view(request):
    """Show all encoded images belonging to the logged-in user."""
    encoded_images = EncodedImage.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'steganography_app/dashboard.html', {
        'encoded_images': encoded_images,
    })


# ─────────────────────────────────────────────────────────────────────────────
# ENCODE VIEW
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def encode_view(request):
    """
    Encode a secret message into an image.

    Flow:
      GET  → show EncodeForm + capacity hint
      POST → validate → encrypt message → LSB encode → save → confirm
    """
    form = EncodeForm(request.POST or None, request.FILES or None)
    capacity_info = None

    if request.method == 'POST':
        if form.is_valid():
            image_file = form.cleaned_data['image']
            secret_message = form.cleaned_data['message']
            password = form.cleaned_data['password']
            label = form.cleaned_data.get('label', '')

            try:
                # ── 1. Open image to check capacity ───────────────────────
                pil_img = Image.open(image_file).convert('RGB')
                capacity_bytes = get_image_capacity(pil_img)
                image_file.seek(0)  # Reset file pointer after PIL read

                # ── 2. Encrypt the message ─────────────────────────────────
                encrypted = encrypt_message(secret_message, password)

                # ── 3. Check encrypted payload fits ───────────────────────
                payload_size = len(encrypted.encode('utf-8'))
                if payload_size > capacity_bytes:
                    messages.error(
                        request,
                        f'Message too large after encryption. '
                        f'Max: {capacity_bytes} bytes, yours: {payload_size} bytes. '
                        f'Use a larger image or shorter message.'
                    )
                    return render(request, 'steganography_app/encode.html', {'form': form})

                # ── 4. LSB encode ──────────────────────────────────────────
                image_file.seek(0)
                encoded_output = encode_image(image_file, encrypted)

                # ── 5. Save original image ─────────────────────────────────
                image_file.seek(0)
                orig_content = ContentFile(image_file.read(), name=f'original_{image_file.name}')

                # ── 6. Save encoded PNG ────────────────────────────────────
                encoded_content = ContentFile(
                    encoded_output.read(),
                    name=f'encoded_{request.user.username}.png'
                )

                # ── 7. Create database record ──────────────────────────────
                encoded_record = EncodedImage.objects.create(
                    user=request.user,
                    original_image=orig_content,
                    encoded_image=encoded_content,
                    label=label
                )

                messages.success(
                    request,
                    f'✅ Message successfully encoded and hidden in your image!'
                )
                return redirect('dashboard')

            except ValueError as e:
                messages.error(request, f'Encoding error: {e}')
            except Exception as e:
                logger.error(f'Unexpected encode error for user {request.user}: {e}')
                messages.error(request, 'An unexpected error occurred. Please try again.')

        else:
            messages.error(request, 'Please fix the form errors below.')

    # Show capacity info if image already uploaded (GET with image)
    return render(request, 'steganography_app/encode.html', {
        'form': form,
        'capacity_info': capacity_info,
    })


# ─────────────────────────────────────────────────────────────────────────────
# DECODE VIEWS (Multi-step)
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def decode_view(request):
    """
    Decode step 1: Upload encoded image + password → triggers OTP email.
    """
    form = DecodeInitForm(request.POST or None, request.FILES or None)

    if request.method == 'POST' and form.is_valid():
        password = form.cleaned_data['password']
        image_file = form.cleaned_data.get('image')

        if not image_file:
            messages.error(request, 'Please upload an encoded image.')
            return render(request, 'steganography_app/decode.html', {'form': form})

        # Store image data and password in session for step 2
        image_bytes = image_file.read()
        request.session['decode_image_bytes'] = list(image_bytes)  # JSON-serialisable
        request.session['decode_password'] = password
        request.session['decode_image_unique_id'] = None  # direct upload, not shareable

        return _send_otp_and_redirect(request)

    return render(request, 'steganography_app/decode.html', {'form': form})


@login_required
def decode_link_view(request, unique_id):
    """
    Decode via shareable link /decode/<unique_id>/.
    Step 1: Password entry → OTP. The image is loaded from the database.
    """
    encoded_record = get_object_or_404(EncodedImage, unique_id=unique_id)

    form = DecodeInitForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        password = form.cleaned_data['password']

        # Store image path (from DB) and password in session
        request.session['decode_image_unique_id'] = str(unique_id)
        request.session['decode_password'] = password
        request.session.pop('decode_image_bytes', None)

        return _send_otp_and_redirect(request)

    return render(request, 'steganography_app/decode_link.html', {
        'form': form,
        'encoded_record': encoded_record,
    })


def _send_otp_and_redirect(request):
    """
    Internal helper: generate OTP, save to DB, send email, redirect to OTP page.
    """
    # Invalidate any old unverified OTPs for this user
    OTPRecord.objects.filter(user=request.user, is_verified=False).delete()

    otp = generate_otp()
    unique_id = request.session.get('decode_image_unique_id')

    OTPRecord.objects.create(
        user=request.user,
        otp=otp,
        image_unique_id=unique_id,
    )

    # Send OTP email (console backend prints to terminal in dev)
    email_sent = send_otp_email(
        user_email=request.user.email,
        otp=otp,
        username=request.user.username
    )

    if email_sent:
        messages.info(
            request,
            f'🔐 A 6-digit OTP has been sent to {request.user.email}. '
            f'It expires in 5 minutes.'
        )
    else:
        messages.warning(
            request,
            'Could not send OTP email. Check server logs / email configuration.'
        )

    return redirect('otp_verify')


@login_required
def otp_verify_view(request):
    """
    Decode step 2: User enters OTP → validate → decode and decrypt message.
    """
    # Guard: make sure a decode session exists
    if 'decode_password' not in request.session:
        messages.error(request, 'Session expired. Please start the decode process again.')
        return redirect('decode')

    form = OTPVerificationForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        input_otp = form.cleaned_data['otp']

        # Fetch the latest unverified OTP for this user
        try:
            otp_record = OTPRecord.objects.filter(
                user=request.user,
                is_verified=False
            ).latest('created_at')
        except OTPRecord.DoesNotExist:
            messages.error(request, 'No OTP found. Please request a new one.')
            return render(request, 'steganography_app/otp_verify.html', {'form': form})

        # ── Check expiry ───────────────────────────────────────────────────
        if otp_record.is_expired():
            otp_record.delete()
            messages.error(request, '⏰ OTP has expired. Please start again.')
            _clear_decode_session(request)
            return redirect('decode')

        # ── Check OTP value ────────────────────────────────────────────────
        if not verify_otp(input_otp, otp_record.otp):
            messages.error(request, '❌ Incorrect OTP. Please try again.')
            return render(request, 'steganography_app/otp_verify.html', {'form': form})

        # ── OTP valid — proceed to decode ──────────────────────────────────
        otp_record.is_verified = True
        otp_record.save()

        password = request.session.get('decode_password')
        unique_id = request.session.get('decode_image_unique_id')
        image_bytes_list = request.session.get('decode_image_bytes')

        try:
            if unique_id:
                # Load from database (shareable link flow)
                encoded_record = EncodedImage.objects.get(unique_id=unique_id)
                image_file = encoded_record.encoded_image.open('rb')
            elif image_bytes_list:
                # Load from session (direct upload flow)
                image_file = BytesIO(bytes(image_bytes_list))
            else:
                raise ValueError("No image available for decoding.")

            # ── LSB decode ─────────────────────────────────────────────────
            encrypted_payload = decode_image(image_file)

            # ── Decrypt with password ──────────────────────────────────────
            original_message = decrypt_message(encrypted_payload, password)

            # Clean up session
            _clear_decode_session(request)

            messages.success(request, '✅ Message successfully decoded and decrypted!')
            return render(request, 'steganography_app/decode_result.html', {
                'message': original_message
            })

        except ValueError as e:
            messages.error(request, f'Decode error: {e}')
            _clear_decode_session(request)
            return redirect('decode')
        except Exception as e:
            logger.error(f'Unexpected decode error for user {request.user}: {e}')
            messages.error(request, 'An unexpected error occurred during decoding.')
            _clear_decode_session(request)
            return redirect('decode')

    return render(request, 'steganography_app/otp_verify.html', {'form': form})


@login_required
def resend_otp_view(request):
    """Resend OTP — invalidates old OTP and sends a fresh one."""
    if 'decode_password' not in request.session:
        messages.error(request, 'Session expired. Please start the decode process again.')
        return redirect('decode')

    return _send_otp_and_redirect(request)


def _clear_decode_session(request):
    """Remove all decode-related keys from session."""
    for key in ['decode_image_bytes', 'decode_password', 'decode_image_unique_id']:
        request.session.pop(key, None)


# ─────────────────────────────────────────────────────────────────────────────
# CAPACITY CHECK (AJAX helper)
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def capacity_check_view(request):
    """
    AJAX endpoint: returns image capacity info when user selects an image.
    Used to show real-time capacity feedback on the encode page.
    """
    from django.http import JsonResponse

    if request.method == 'POST' and request.FILES.get('image'):
        try:
            img = Image.open(request.FILES['image']).convert('RGB')
            capacity = get_image_capacity(img)
            w, h = img.size
            return JsonResponse({
                'success': True,
                'capacity_bytes': capacity,
                'capacity_kb': round(capacity / 1024, 2),
                'width': w,
                'height': h,
            })
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'No image provided'})
