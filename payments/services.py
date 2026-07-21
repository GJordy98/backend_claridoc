"""
Services for the payments application.

Handles Steeve's Payment Hub API calls, license generation,
and email dispatch after a successful payment.

Providers:
  1 = Orange Money (OM)
  2 = MTN Mobile Money (MoMo)
  3 = Carte Bancaire (Visa / Mastercard)
"""
# pylint: disable=no-member
import logging
import secrets
import string
from datetime import date, timedelta

import requests
from django.conf import settings
from django.core.mail import send_mail

from accounts.models import Licence
from .models import SteevHubTransaction

logger = logging.getLogger(__name__)

# ─── Forfait mapping ──────────────────────────────────────────────────────────
FORFAIT_POSTES_MAP = {
    '2 PCs (Démo)': 2,   # Forfait démonstration
    '1-3 PCs':   1,
    '4-8 PCs':   4,
    '9-15 PCs':  9,
    '16+ PCs':  16,
}

FORFAIT_DUREE_MAP = {
    'Démo (2 semaines)':  14,   # Forfait démonstration
    'Mensuel':      30,
    'Trimestriel':  90,
    'Semestriel':  180,
    'Annuel':      365,
}

# ─── Provider mapping ─────────────────────────────────────────────────────────
PROVIDER_NAMES = {1: 'Orange Money', 2: 'MTN MoMo', 3: 'Carte Bancaire'}


def _generate_activation_code(length: int = 20) -> str:
    """Génère un code d'activation unique alphanumérique."""
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def initiate_steeve_payment(payment_request, telephone: str, provider_id: int) -> dict:
    """
    Initie un paiement via le hub de Steeve et retourne la référence de transaction.

    Args:
        payment_request: Instance de PaymentRequest.
        telephone: Numéro du payeur au format international (ex: 237XXXXXXXXX).
        provider_id: ID du provider (1=OM, 2=MoMo, 3=Carte).

    Returns:
        dict avec 'hub_reference', 'pay_token', 'message'.

    Raises:
        RuntimeError: Si le hub retourne une erreur ou si la réponse est invalide.
    """
    base_url = settings.STEEVE_HUB_BASE_URL.rstrip('/')
    token = settings.STEEVE_HUB_TOKEN

    if not token:
        raise RuntimeError("STEEVE_HUB_TOKEN non configuré dans les variables d'environnement.")

    montant = int(payment_request.montant)

    payload = {
        "amount": str(montant),
        "provider_id": str(provider_id),
        "module_origin": "CLARIDOC PRO",
        "telephone": telephone,
    }

    headers = {
        "Authorization": f"HubToken {token}",
        "Content-Type": "application/json",
    }

    logger.info(
        "Initiation paiement Steeve Hub — provider=%s tel=%s montant=%s XAF ref_demande=%s",
        PROVIDER_NAMES.get(provider_id, '?'), telephone, montant, payment_request.id
    )

    try:
        response = requests.post(
            f"{base_url}/api-v1/paiement/",
            json=payload,
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
    except requests.exceptions.Timeout as exc:
        logger.error("Timeout lors de l'appel au hub de paiement Steeve.")
        raise RuntimeError(
            "Le hub de paiement ne répond pas. Réessayez dans quelques instants."
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        logger.error("Impossible de joindre le hub de paiement Steeve à %s", base_url)
        raise RuntimeError("Connexion au hub de paiement impossible.") from exc
    except requests.exceptions.HTTPError as exc:
        logger.error("Erreur HTTP hub Steeve: %s — %s", exc.response.status_code, exc.response.text)
        raise RuntimeError(f"Erreur du hub de paiement: {exc.response.status_code}") from exc

    data = response.json()
    logger.debug("Réponse hub Steeve: %s", data)

    if not data.get("status"):
        msg = data.get("message", "Erreur inconnue du hub de paiement.")
        logger.error("Hub Steeve — statut négatif: %s", msg)
        raise RuntimeError(msg)

    payment_data = data.get("payment", {})
    hub_reference = payment_data.get("reference")
    pay_token = payment_data.get("pay_token")
    provider_payload = data.get("provider_payload", {})

    if not hub_reference:
        logger.error("Hub Steeve — référence manquante dans la réponse: %s", data)
        raise RuntimeError("Référence de paiement introuvable dans la réponse du hub.")

    # Vérifier si le provider a rejeté immédiatement (ex: solde insuffisant)
    provider_data = provider_payload.get("data", {})
    provider_status = (
        provider_data.get("status")
        or provider_payload.get("status")
        or ""
    ).upper()
    if provider_status == "FAILED":
        error_msg = (
            provider_payload.get("message")
            or provider_data.get("inittxnmessage")
            or "Paiement refusé par le provider."
        )
        logger.warning("Provider a rejeté le paiement: %s", error_msg)
        raise RuntimeError(error_msg)

    # Enregistrer la transaction en base
    SteevHubTransaction.objects.create(  # type: ignore[attr-defined]
        payment_request=payment_request,
        hub_reference=hub_reference,
        pay_token=pay_token,
        provider_id=provider_id,
        telephone=telephone,
        amount=payment_request.montant,
        currency='XAF',
        status='PENDING',
        raw_response=data,
    )

    logger.info(
        "Transaction créée — hub_ref=%s pay_token=%s",
        hub_reference, pay_token
    )

    return {
        "hub_reference": hub_reference,
        "pay_token": pay_token,
        "message": data.get("message", "Paiement initié. Veuillez valider sur votre téléphone."),
    }


def check_steeve_payment_status(hub_reference: str) -> dict:
    """
    Vérifie le statut d'un paiement auprès du hub de Steeve.

    Args:
        hub_reference: La référence UUID retournée lors de l'initiation.

    Returns:
        dict avec le statut actuel (ex: {'status': 'SUCCESS', 'data': {...}}).
    """
    base_url = settings.STEEVE_HUB_BASE_URL.rstrip('/')
    token = settings.STEEVE_HUB_TOKEN

    headers = {
        "Authorization": f"HubToken {token}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.get(
            f"{base_url}/api-v1/paiement/payment-status/",
            params={"reference": hub_reference},
            headers=headers,
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        payment_data = data.get("payment", data)

        raw_status = payment_data.get("status", "UNKNOWN").upper()

        if raw_status in ("SUCCESS", "SUCCESSFULL"):
            statut_normalise = "SUCCESS"
        else:
            statut_normalise = raw_status

        return {
            "status": statut_normalise,
            "data": payment_data,
        }
    except requests.exceptions.RequestException as exc:
        logger.error("Erreur vérification statut paiement %s: %s", hub_reference, exc)
        return {"status": "UNKNOWN", "data": {}}


def handle_payment_success(tx: SteevHubTransaction) -> None:
    """
    Appelée après confirmation du paiement (via webhook ou polling).

    - Met à jour le statut de la PaymentRequest → VALIDE.
    - Crée ou renouvelle la Licence de la succursale.
    - Envoie l'email d'activation au client.
    """
    payment_request = tx.payment_request
    payment_request.statut = payment_request.StatutPaiement.VALIDE
    payment_request.save()

    succursale = payment_request.succursale_cible
    if not succursale:
        if payment_request.nom_nouvelle_succursale:
            from accounts.models import Succursale  # pylint: disable=import-outside-toplevel
            succursale = Succursale.objects.create(  # type: ignore[attr-defined]  # noqa: E501
                client=payment_request.client,
                nom=payment_request.nom_nouvelle_succursale
            )
            payment_request.succursale_cible = succursale
            payment_request.save()
            logger.info("Nouvelle succursale créée : %s", succursale.nom)
        else:
            logger.error(
                "Pas de succursale_cible ni de nom_nouvelle_succursale sur PaymentRequest id=%s",
                payment_request.id
            )
            return

    # Préparation des données de la licence
    duree_jours = FORFAIT_DUREE_MAP.get(payment_request.forfait_duree, 30)
    date_fin_initiale = date.today() + timedelta(days=duree_jours)
    max_machines = FORFAIT_POSTES_MAP.get(payment_request.forfait_postes, 1)
    code_activation = _generate_activation_code()

    # Création ou renouvellement de la licence
    licence, created = Licence.objects.get_or_create(  # type: ignore[attr-defined]
        succursale=succursale,
        defaults={
            'date_fin': date_fin_initiale,
            'max_machines': max_machines,
            'code_activation': code_activation,
        }
    )

    if not created:
        # Renouvellement : prolonger depuis la date de fin (si future) ou d'aujourd'hui
        is_future = licence.date_fin and licence.date_fin > date.today()
        base_date = licence.date_fin if is_future else date.today()
        licence.date_fin = base_date + timedelta(days=duree_jours)
        licence.max_machines = max_machines
        licence.code_activation = code_activation
        licence.save()

    logger.info(
        "Licence créée/renouvelée pour succursale=%s — fin=%s code=%s",
        succursale.nom, licence.date_fin, licence.code_activation
    )

    # Mettre à jour le statut du client
    client = payment_request.client
    client.statut = client.StatutClient.ACTIF
    client.save()

    # Envoi de l'email d'activation
    _send_activation_email(payment_request, licence)


def _send_activation_email(payment_request, licence: Licence) -> None:
    """Envoie un email d'activation avec le code de licence au client."""
    client = payment_request.client
    succursale = licence.succursale  # type: ignore[attr-defined]
    email_destinataire = client.email_contact

    # Collecter tous les destinataires potentiels
    destinataires = set()
    if email_destinataire:
        destinataires.add(email_destinataire)

    from accounts.models import User  # pylint: disable=import-outside-toplevel
    user_emails = User.objects.filter(
        client=client, is_active=True
    ).values_list('email', flat=True)
    for email in user_emails:
        if email:
            destinataires.add(email)

    if not destinataires:
        logger.warning(
            "Aucun destinataire trouvé pour le client %s — email non envoyé.", client.nom
        )
        return

    recipient_list = list(destinataires)
    nom_succursale = succursale.nom if succursale else 'Succursale'

    sujet = f"[ClariDoc Pro] Votre licence est activée — {nom_succursale}"

    message = (
        f"Bonjour,\n\n"
        f"Votre paiement a été validé avec succès.\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"DÉTAILS DE VOTRE LICENCE\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"  Client        : {client.nom}\n"
        f"  Succursale    : {nom_succursale}\n"
        f"  Forfait       : {payment_request.forfait_postes} — {payment_request.forfait_duree}\n"
        f"  Machines max  : {licence.max_machines}\n"
        f"  Valable jusqu': {licence.date_fin.strftime('%d/%m/%Y')}\n\n"
        f"  CODE D'ACTIVATION : {licence.code_activation}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"Rendez-vous dans votre application ClariDoc Pro, rubrique\n"
        f"'Activation de licence', et saisissez le code ci-dessus.\n\n"
        f"En cas de difficulté, contactez notre support.\n\n"
        f"Cordialement,\n"
        f"L'équipe ClariDoc Pro\n"
    )

    try:
        print("\n" + "="*50)
        print(f"📧 ENVOI EMAIL LICENCE à: {', '.join(recipient_list)}")
        print("="*50 + "\n")
        send_mail(
            subject=sujet,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipient_list,
            fail_silently=False,
        )
        logger.info("Email d'activation envoyé à : %s", ", ".join(recipient_list))
        print("✅ EMAIL ENVOYÉ AVEC SUCCÈS !")
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Échec envoi email aux destinataires %s: %s", recipient_list, exc)
