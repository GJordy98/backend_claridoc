import os
import logging
from django.core.mail import EmailMultiAlternatives
from django.conf import settings

logger = logging.getLogger(__name__)


def send_otp_email(email: str, otp_code: str, first_name: str = "") -> bool:
    """
    Envoie un email OTP à l'adresse indiquée via Brevo SMTP.

    Args:
        email:      Adresse du destinataire.
        otp_code:   Code OTP à 6 chiffres.
        first_name: Prénom du destinataire (optionnel, pour personnaliser l'email).

    Returns:
        True si l'email a été envoyé, False en cas d'erreur.
    """
    prenom = first_name if first_name else "Utilisateur"
    subject = "Votre code de vérification ClariDoc Pro"

    # ── Corps texte brut (fallback) ─────────────────────────────────────────
    text_content = (
        f"Bonjour {prenom},\n\n"
        f"Votre code de vérification ClariDoc Pro est : {otp_code}\n\n"
        f"Ce code est valable 15 minutes.\n"
        f"Si vous n'avez pas demandé ce code, ignorez cet email.\n\n"
        f"— L'équipe ClariDoc Pro"
    )

    # ── Corps HTML ───────────────────────────────────────────────────────────
    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Code OTP ClariDoc Pro</title>
</head>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f8;padding:40px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0"
             style="background:#ffffff;border-radius:12px;overflow:hidden;
                    box-shadow:0 4px 24px rgba(0,0,0,0.08);">

        <!-- En-tête -->
        <tr>
          <td style="background:linear-gradient(135deg,#1e3a5f 0%,#2563eb 100%);
                     padding:36px 40px;text-align:center;">
            <h1 style="margin:0;color:#ffffff;font-size:26px;font-weight:700;
                       letter-spacing:1px;">ClariDoc Pro</h1>
            <p style="margin:6px 0 0;color:#93c5fd;font-size:13px;">
              Vérification de votre compte
            </p>
          </td>
        </tr>

        <!-- Corps -->
        <tr>
          <td style="padding:40px 40px 20px;">
            <p style="margin:0 0 8px;color:#374151;font-size:16px;">
              Bonjour <strong>{prenom}</strong>,
            </p>
            <p style="margin:0 0 28px;color:#6b7280;font-size:14px;line-height:1.6;">
              Pour activer votre compte ClariDoc Pro, veuillez saisir le code
              de vérification ci-dessous. Il est valable <strong>15 minutes</strong>.
            </p>

            <!-- Code OTP -->
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr><td align="center" style="padding:20px 0;">
                <div style="display:inline-block;background:#f0f7ff;border:2px dashed #2563eb;
                            border-radius:12px;padding:20px 40px;">
                  <span style="font-size:42px;font-weight:800;letter-spacing:14px;
                               color:#1e3a5f;font-family:'Courier New',monospace;">
                    {otp_code}
                  </span>
                </div>
              </td></tr>
            </table>

            <p style="margin:28px 0 0;color:#9ca3af;font-size:12px;text-align:center;
                      line-height:1.6;">
              Si vous n'avez pas créé de compte ClariDoc Pro,<br>
              ignorez simplement cet email.
            </p>
          </td>
        </tr>

        <!-- Pied de page -->
        <tr>
          <td style="background:#f8fafc;border-top:1px solid #e5e7eb;
                     padding:20px 40px;text-align:center;">
            <p style="margin:0;color:#9ca3af;font-size:11px;">
              &copy; 2025 ClariDoc Pro &mdash; Ce message est envoyé automatiquement,
              merci de ne pas y répondre.
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""

    try:
        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[email],
        )
        msg.attach_alternative(html_content, "text/html")
        msg.send(fail_silently=False)
        logger.info("OTP email envoyé à %s", email)
        return True
    except Exception as exc:                          # pylint: disable=broad-except
        logger.error("Échec envoi OTP à %s : %s", email, exc)
        return False


import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def generate_aes_credentials():
    """Génère une clé AES-256 et un IV aléatoires au format Hex."""
    key = os.urandom(32)
    iv = os.urandom(16)
    return key.hex().upper(), iv.hex().upper()

def encrypt_license_data(payload_dict, aes_key_hex, iv_hex):
    """
    Chiffre un dictionnaire JSON avec AES-256-CBC et PKCS7 padding.
    Compatible avec le CryptoManager de l'application C# ClariDoc.
    """
    key = bytes.fromhex(aes_key_hex)
    iv = bytes.fromhex(iv_hex)
    
    # Préparer les données
    payload_str = json.dumps(payload_dict)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(payload_str.encode('utf-8')) + padder.finalize()
    
    # Chiffrer
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(padded_data) + encryptor.finalize()
    
    # Retourner en Base64
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt_license_data(encrypted_base64, aes_key_hex, iv_hex):
    """
    Déchiffre la licence (utile pour les tests backend).
    """
    key = bytes.fromhex(aes_key_hex)
    iv = bytes.fromhex(iv_hex)
    encrypted_bytes = base64.b64decode(encrypted_base64)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return json.loads(data.decode('utf-8'))
def encrypt_simple_string(text, aes_key_hex, iv_hex):
    """
    Chiffre une simple chaîne (sans JSON) avec AES-256-CBC.
    Idéal pour les mots de passe FTP.
    """
    key = bytes.fromhex(aes_key_hex)
    iv = bytes.fromhex(iv_hex)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode('utf-8')) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(padded_data) + encryptor.finalize()
    
    return base64.b64encode(encrypted_bytes).decode('utf-8')
