from django.contrib import admin
from .models import EncodedImage, OTPRecord


@admin.register(EncodedImage)
class EncodedImageAdmin(admin.ModelAdmin):
    list_display = ('user', 'unique_id', 'label', 'created_at')
    list_filter = ('user', 'created_at')
    search_fields = ('user__username', 'label')
    readonly_fields = ('unique_id', 'created_at')


@admin.register(OTPRecord)
class OTPRecordAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_verified', 'created_at', 'image_unique_id')
    list_filter = ('is_verified',)
    readonly_fields = ('created_at',)
