"""
Models for the Steganography Application.

EncodedImage: Stores encoded image metadata per user.
OTPRecord:    Tracks OTP codes for 2FA decode verification.
"""

import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings


class EncodedImage(models.Model):
    """
    Stores each encoding session — original image, encoded result,
    unique shareable link, and ownership.
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='encoded_images'
    )
    # Original uploaded image (JPG/PNG)
    original_image = models.ImageField(
        upload_to='original_images/%Y/%m/',
        null=True,
        blank=True
    )
    # Encoded output image (always PNG)
    encoded_image = models.ImageField(
        upload_to='encoded_images/%Y/%m/'
    )
    # Unique ID for shareable decode links
    unique_id = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True
    )
    # Optional label for the user's reference
    label = models.CharField(max_length=255, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Encoded Image'
        verbose_name_plural = 'Encoded Images'

    def __str__(self):
        return f"{self.user.username} — {self.unique_id} ({self.created_at:%Y-%m-%d})"

    def get_shareable_url(self):
        """Returns the relative decode URL for sharing."""
        return f"/decode/{self.unique_id}/"


class OTPRecord(models.Model):
    """
    Stores OTP codes tied to users for 2FA during decode.
    OTPs expire after OTP_EXPIRY_MINUTES (default: 5 minutes).
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='otp_records'
    )
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    # Store which image this OTP is meant to unlock
    image_unique_id = models.UUIDField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'OTP Record'

    def __str__(self):
        return f"OTP for {self.user.username} — {'verified' if self.is_verified else 'pending'}"

    def is_expired(self):
        """Check if OTP is older than OTP_EXPIRY_MINUTES."""
        expiry_minutes = getattr(settings, 'OTP_EXPIRY_MINUTES', 5)
        return timezone.now() > self.created_at + timezone.timedelta(minutes=expiry_minutes)
