"""
urls.py — URL routes for the Steganography Application.
"""
from django.urls import path
from . import views

urlpatterns = [
    # ── Public ────────────────────────────────────────────────────────────────
    path('', views.home_view, name='home'),

    # ── Authentication ────────────────────────────────────────────────────────
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # ── Core App (login required) ─────────────────────────────────────────────
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('encode/', views.encode_view, name='encode'),

    # Decode: direct upload flow
    path('decode/', views.decode_view, name='decode'),

    # Decode: shareable link flow
    path('decode/<uuid:unique_id>/', views.decode_link_view, name='decode_link'),

    # OTP verification step (shared by both decode flows)
    path('decode/verify-otp/', views.otp_verify_view, name='otp_verify'),

    # Resend OTP
    path('decode/resend-otp/', views.resend_otp_view, name='resend_otp'),

    # AJAX capacity check
    path('api/capacity-check/', views.capacity_check_view, name='capacity_check'),
]
