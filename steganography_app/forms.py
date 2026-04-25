"""
forms.py — All forms for the Steganography Application.

Forms:
  - UserSignupForm    : Registration with email
  - EncodeForm        : Upload image + message + password
  - DecodeInitForm    : Upload encoded image + password (triggers OTP)
  - OTPVerificationForm: Enter 6-digit OTP
"""

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


# ─────────────────────────────────────────────────────────────────────────────
# AUTHENTICATION FORMS
# ─────────────────────────────────────────────────────────────────────────────

class UserSignupForm(UserCreationForm):
    """Extended signup form that requires an email address (needed for OTP)."""
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'your@email.com'
        }),
        help_text='Required — OTP codes are sent to this address.'
    )

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Apply Bootstrap classes to all fields
        for field_name, field in self.fields.items():
            if not field.widget.attrs.get('class'):
                field.widget.attrs['class'] = 'form-control'
        self.fields['username'].widget.attrs['placeholder'] = 'Choose a username'
        self.fields['password1'].widget.attrs['placeholder'] = 'Create a strong password'
        self.fields['password2'].widget.attrs['placeholder'] = 'Confirm password'

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user


# ─────────────────────────────────────────────────────────────────────────────
# ENCODE FORM
# ─────────────────────────────────────────────────────────────────────────────

class EncodeForm(forms.Form):
    """
    Form for encoding a secret message into an image.
    Accepts any common image format; all are converted to PNG.
    """
    image = forms.ImageField(
        label='Cover Image',
        widget=forms.ClearableFileInput(attrs={
            'class': 'form-control',
            'accept': 'image/*'
        }),
        help_text='Upload any image (JPG, PNG, BMP). Larger images = more capacity.'
    )
    message = forms.CharField(
        label='Secret Message',
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 5,
            'placeholder': 'Enter the secret message to hide...'
        }),
        max_length=50000,
        help_text='The message will be encrypted before embedding.'
    )
    password = forms.CharField(
        label='Encryption Password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Strong password to encrypt the message'
        }),
        min_length=6,
        help_text='Remember this password — it is required to decode.'
    )
    label = forms.CharField(
        label='Label (optional)',
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'e.g. "Project X secret"'
        }),
        max_length=255
    )


# ─────────────────────────────────────────────────────────────────────────────
# DECODE FORMS (Multi-step: image+password → OTP → result)
# ─────────────────────────────────────────────────────────────────────────────

class DecodeInitForm(forms.Form):
    """
    Step 1 of decode: user uploads the encoded image and enters the password.
    Submitting this triggers OTP generation and email delivery.
    """
    image = forms.ImageField(
        label='Encoded Image',
        required=False,  # Not needed if using shareable link
        widget=forms.ClearableFileInput(attrs={
            'class': 'form-control',
            'accept': 'image/png'
        }),
        help_text='Upload the PNG image containing the hidden message.'
    )
    password = forms.CharField(
        label='Decryption Password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password used during encoding'
        }),
        min_length=1,
    )

    def clean(self):
        """Image field is only required when not using a shareable link."""
        cleaned_data = super().clean()
        return cleaned_data


class OTPVerificationForm(forms.Form):
    """
    Step 2 of decode: user enters the 6-digit OTP received via email.
    """
    otp = forms.CharField(
        label='One-Time Password',
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-control text-center otp-input',
            'placeholder': '000000',
            'maxlength': '6',
            'inputmode': 'numeric',
            'autocomplete': 'one-time-code',
            'pattern': '[0-9]{6}'
        }),
        help_text='Enter the 6-digit code sent to your email.'
    )

    def clean_otp(self):
        otp = self.cleaned_data.get('otp', '').strip()
        if not otp.isdigit():
            raise forms.ValidationError('OTP must contain digits only.')
        return otp
