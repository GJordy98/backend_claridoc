"""Script to test the SMTP email configuration by sending a test message via Django."""
import os

import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'claridoc_api.settings')
django.setup()

from django.conf import settings  # noqa: E402
from django.core.mail import send_mail  # noqa: E402

try:
    print(f"Tentative d'envoi d'email via {settings.EMAIL_HOST}...")
    send_mail(
        subject="Test de connexion ClariDoc",
        message="Ceci est un test pour vérifier la configuration SMTP.",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=["kevanjordy@gmail.com"],
        fail_silently=False,
    )
    print("SUCCESS: Email envoye !")
except OSError as e:
    print(f"ERROR: Echec de l'envoi : {e}")
