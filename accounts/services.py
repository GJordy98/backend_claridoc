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
        print(f"DEBUG: Tentative d'envoi OTP via SMTP avec l'expéditeur : {settings.DEFAULT_FROM_EMAIL}")
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Bascule de format de chiffrement des licences / credentials.
#   True  -> emet du AES-256-GCM v1 (authentifie, nonce aleatoire) -- RECOMMANDE
#   False -> emet de l'AES-256-CBC (ancien format, pour la phase de migration)
# Pilotable sans redeploiement via la variable d'environnement USE_GCM_ENCRYPTION.
# Le DECHIFFREMENT detecte le format automatiquement quel que soit ce reglage.
USE_GCM = os.environ.get('USE_GCM_ENCRYPTION', '1') == '1'

GCM_VERSION = b'\x01'   # prefixe de version : 0x01 = AES-256-GCM v1
GCM_NONCE_LEN = 12      # 96 bits, taille de nonce recommandee pour GCM


def generate_aes_credentials():
    """Genere une cle AES-256 et un IV/nonce de base aleatoires au format Hex."""
    key = os.urandom(32)
    iv = os.urandom(16)
    return key.hex().upper(), iv.hex().upper()


# ---------------------------------------------------------------------------
# AES-256-GCM (nouveau format authentifie ; nonce aleatoire par message)
# Format : base64( 0x01 || nonce(12) || ciphertext || tag(16) )
# Compatible octet pour octet avec CryptoManager.DechiffrerGcm cote C#.
# ---------------------------------------------------------------------------
def _gcm_encrypt(plaintext, aes_key_hex, aad=b''):
    key = bytes.fromhex(aes_key_hex)
    nonce = os.urandom(GCM_NONCE_LEN)
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)   # = ciphertext || tag(16)
    return base64.b64encode(GCM_VERSION + nonce + ct_and_tag).decode('utf-8')


def _gcm_decrypt(encoded, aes_key_hex, aad=b''):
    key = bytes.fromhex(aes_key_hex)
    blob = base64.b64decode(encoded)
    if blob[:1] != GCM_VERSION:
        raise ValueError("Prefixe GCM absent : ce n'est pas un blob AES-GCM v1.")
    nonce = blob[1:1 + GCM_NONCE_LEN]
    ct_and_tag = blob[1 + GCM_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct_and_tag, aad)   # leve InvalidTag si altere


def _is_gcm_blob(encoded):
    try:
        return base64.b64decode(encoded)[:1] == GCM_VERSION
    except Exception:
        return False


# ---------------------------------------------------------------------------
# AES-256-CBC (ancien format ; conserve pour dechiffrer les licences deja emises)
# ---------------------------------------------------------------------------
def _cbc_encrypt(plaintext, aes_key_hex, iv_hex):
    key = bytes.fromhex(aes_key_hex)
    iv = bytes.fromhex(iv_hex)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return base64.b64encode(enc.update(padded) + enc.finalize()).decode('utf-8')


def _cbc_decrypt(encoded, aes_key_hex, iv_hex):
    key = bytes.fromhex(aes_key_hex)
    iv = bytes.fromhex(iv_hex)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(base64.b64decode(encoded)) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ---------------------------------------------------------------------------
# API publique -- signatures inchangees (iv_hex conserve pour les appelants).
# Le dechiffrement auto-detecte GCM vs CBC : aucun risque sur les licences
# deja emises pendant la migration.
# ---------------------------------------------------------------------------
def encrypt_license_data(payload_dict, aes_key_hex, iv_hex=None):
    """Chiffre un dict JSON. AES-GCM si USE_GCM, sinon AES-CBC (legacy)."""
    data = json.dumps(payload_dict).encode('utf-8')
    if USE_GCM:
        return _gcm_encrypt(data, aes_key_hex)
    return _cbc_encrypt(data, aes_key_hex, iv_hex)


def encrypt_simple_string(text, aes_key_hex, iv_hex=None):
    """Chiffre une chaine simple (ex. mot de passe FTP). AES-GCM ou AES-CBC."""
    data = text.encode('utf-8')
    if USE_GCM:
        return _gcm_encrypt(data, aes_key_hex)
    return _cbc_encrypt(data, aes_key_hex, iv_hex)


def decrypt_simple_string(encrypted_base64, aes_key_hex, iv_hex=None):
    """Dechiffre une chaine (auto-detection du format GCM ou CBC)."""
    if _is_gcm_blob(encrypted_base64):
        return _gcm_decrypt(encrypted_base64, aes_key_hex).decode('utf-8')
    return _cbc_decrypt(encrypted_base64, aes_key_hex, iv_hex).decode('utf-8')


def decrypt_license_data(encrypted_base64, aes_key_hex, iv_hex=None):
    """Dechiffre la licence (auto-detection GCM/CBC) et renvoie le dict JSON."""
    return json.loads(decrypt_simple_string(encrypted_base64, aes_key_hex, iv_hex))


# ---------------------------------------------------------------------------
#  Configuration FTP effective d'une succursale
# ---------------------------------------------------------------------------

def cles_licence(succursale, creer=False):
    """(aes_key_hex, iv_hex) de la licence d'une succursale, ou (None, None).

    Avec creer=True, les cles ABSENTES sont generees et enregistrees. Une licence
    jamais activee n'en possede pas encore : la vue de verification les cree au
    vol, mais s'appuyer sur cet ordre rendrait la resolution FTP dependante du
    chemin d'appel — l'ecran d'administration, lui, verrait une agence vide.
    L'operation est idempotente et sans effet de bord visible : une licence sans
    cle est de toute facon inutilisable.
    """
    lic = getattr(succursale, 'licence', None)
    if not lic:
        return None, None
    if not lic.aes_key_hex:
        if not creer:
            return None, None
        aes, iv = generate_aes_credentials()
        lic.aes_key_hex, lic.iv_hex = aes, iv
        lic.save(update_fields=['aes_key_hex', 'iv_hex'])
    return lic.aes_key_hex, lic.iv_hex


def resoudre_config_ftp(succursale):
    """Configuration FTP EFFECTIVE d'une succursale, avec repli sur le client.

    Le modele prevoit une configuration FTP par succursale, mais en pratique
    chaque societe cliente possede UN compte FileZilla partage par ses agences.
    Une agence creee sans configuration (le champ est vide par defaut) rendait
    donc l'application inutilisable, avec un message accusant le serveur de
    fichiers alors que l'agence n'avait simplement jamais ete configuree.

    Comportement par DEFAUT : une succursale sans mot de passe FTP herite de la
    configuration d'une autre succursale DU MEME CLIENT qui en possede une.
    Le mot de passe est DECHIFFRE avec la cle de licence de la succursale de
    reference puis RECHIFFRE avec celle de la demandeuse : chaque licence a sa
    propre cle, une simple recopie du texte chiffre donnerait un mot de passe
    illisible cote application.

    EXCEPTION : une succursale qui possede son propre mot de passe garde
    integralement sa configuration. Le repli ne concerne que le champ vide, si
    bien qu'une agence a compte FTP distinct n'est jamais ecrasee.

    Rien n'est ecrit en base : la resolution est calculee a chaque appel, donc
    une modification de la configuration de reference se propage aussitot.

    Renvoie un dict aux cles ftp_host, ftp_port, ftp_user, ftp_password_enc,
    ftp_fingerprint, ftp_base_path, storage_mode, plus deux cles de diagnostic :
      herite_de  : id de la succursale source, ou None
      configuree : False si NI la succursale NI le client n'ont de configuration
                   (cas d'un client entierement neuf) -> l'appelant doit le dire
                   clairement plutot que de laisser croire a une panne serveur.
    """
    propre = {
        'ftp_host': succursale.ftp_host,
        'ftp_port': succursale.ftp_port,
        'ftp_user': succursale.ftp_user,
        'ftp_password_enc': succursale.ftp_password_enc,
        'ftp_fingerprint': succursale.ftp_fingerprint,
        'ftp_base_path': succursale.ftp_base_path,
        'storage_mode': succursale.storage_mode,
        'herite_de': None,
        'configuree': bool(succursale.ftp_password_enc),
    }

    if succursale.ftp_password_enc:
        return propre

    # creer=True : la succursale destinataire DOIT disposer d'une cle pour qu'on
    # puisse rechiffrer a son intention. La reference, elle, n'est jamais
    # modifiee — on ne fait que lire sa configuration.
    aes_dst, iv_dst = cles_licence(succursale, creer=True)
    if not aes_dst:
        # Aucune licence rattachee : rien a rechiffrer, on renvoie tel quel.
        return propre

    # Import local : ce module est importe par models.py au chargement de
    # l'application, un import global de Succursale creerait un cycle.
    from .models import Succursale  # pylint: disable=import-outside-toplevel

    references = (
        Succursale.objects
        .filter(client=succursale.client)
        .exclude(id=succursale.id)
        .exclude(ftp_password_enc__isnull=True)
        .exclude(ftp_password_enc='')
        .order_by('id')
    )

    for ref in references:
        aes_src, iv_src = cles_licence(ref)
        if not aes_src:
            continue
        try:
            clair = decrypt_simple_string(ref.ftp_password_enc, aes_src, iv_src)
        except Exception:  # pylint: disable=broad-except
            # Reference illisible (cle regeneree, format inattendu) : on essaie
            # la suivante plutot que de faire echouer toute la resolution.
            continue
        try:
            rechiffre = encrypt_simple_string(clair, aes_dst, iv_dst)
        except Exception:  # pylint: disable=broad-except
            continue

        # On herite du BLOC COMPLET, pas du seul mot de passe : un compte
        # emprunte au client combine a l'hote ou au chemin par defaut de
        # l'agence produirait une configuration incoherente, donc un echec
        # bien plus difficile a diagnostiquer qu'une absence de configuration.
        return {
            'ftp_host': ref.ftp_host,
            'ftp_port': ref.ftp_port,
            'ftp_user': ref.ftp_user,
            'ftp_password_enc': rechiffre,
            'ftp_fingerprint': ref.ftp_fingerprint,
            'ftp_base_path': ref.ftp_base_path,
            'storage_mode': ref.storage_mode,
            'herite_de': ref.id,
            'configuree': True,
        }

    return propre
