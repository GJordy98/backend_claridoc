"""Views for the payments application: Steeve Hub payment initiation, webhook, and status check."""
import hmac
import hashlib
import json
import logging

from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from rest_framework.permissions import IsAuthenticated

from accounts.models import PaymentRequest
from .models import SteevHubTransaction
from .services import initiate_steeve_payment, check_steeve_payment_status, handle_payment_success

logger = logging.getLogger(__name__)

# Mapping moyen_paiement → provider_id du hub de Steeve
MOYEN_PAIEMENT_TO_PROVIDER = {
    'ORANGE_MONEY': 1,
    'MTN_MOMO':     2,
    'CARTE':        3,
}


class InitiatePaymentView(APIView):
    """
    POST /payments/initiate/

    Initie un paiement via le hub de Steeve pour une demande de licence.
    Requiert un token JWT valide.

    Body:
        payment_request_id (int): ID de la PaymentRequest.
        telephone (str): Numéro du payeur (ex: 237XXXXXXXXX).
        provider_id (int): 1=Orange Money, 2=MTN MoMo, 3=Carte. (optionnel si moyen_paiement défini)
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Initie un paiement via le hub Steeve pour la demande de licence fournie."""
        payment_request_id = request.data.get('payment_request_id')
        telephone = request.data.get('telephone', '').strip()
        provider_id_raw = request.data.get('provider_id')

        # Normalisation automatique du téléphone (Cameroun par défaut : 237)
        if telephone:
            telephone = telephone.replace('+', '').replace(' ', '').strip()
            if len(telephone) == 9 and telephone.startswith(('6', '2')):
                telephone = f"237{telephone}"

        # Validation des champs requis
        if not payment_request_id:
            return Response(
                {'error': 'payment_request_id est requis.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Récupérer la PaymentRequest
        try:
            payment_request = PaymentRequest.objects.get(  # type: ignore
                id=payment_request_id,
                client=request.user.client,
                statut=PaymentRequest.StatutPaiement.EN_ATTENTE
            )
        except PaymentRequest.DoesNotExist:  # type: ignore # pylint: disable=no-member
            return Response(
                {'error': 'Demande de paiement introuvable ou déjà traitée.'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Déterminer le provider_id
        if provider_id_raw:
            try:
                provider_id = int(provider_id_raw)
            except (ValueError, TypeError):
                return Response(
                    {'error': 'provider_id doit être un entier (1=OM, 2=MoMo, 3=Carte).'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            # Déduire depuis le moyen_paiement enregistré dans la demande
            provider_id = MOYEN_PAIEMENT_TO_PROVIDER.get(payment_request.moyen_paiement)
            if not provider_id:
                return Response(
                    {
                        'error': (
                            'provider_id requis (1=Orange Money, 2=MTN MoMo, 3=Carte). '
                            'Ou renseignez moyen_paiement sur la demande.'
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Pour OM et MoMo, le téléphone est obligatoire
        if provider_id in (1, 2) and not telephone:
            return Response(
                {'error': 'Le numéro de téléphone est requis pour Orange Money et MTN MoMo.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Vérifier si une transaction est déjà en cours (idempotence)
        if hasattr(payment_request, 'steeve_transaction'):
            tx = payment_request.steeve_transaction
            if tx.status == 'PENDING':
                return Response(
                    {
                        'message': 'Paiement déjà initié. Veuillez valider sur votre téléphone.',
                        'hub_reference': str(tx.hub_reference),
                        'pay_token': tx.pay_token,
                    },
                    status=status.HTTP_200_OK
                )
            if tx.status == 'SUCCESS':
                return Response(
                    {'message': 'Ce paiement a déjà été validé avec succès.'},
                    status=status.HTTP_200_OK
                )

        try:
            result = initiate_steeve_payment(payment_request, telephone, provider_id)
            return Response(
                {
                    'message': result['message'],
                    'hub_reference': result['hub_reference'],
                    'pay_token': result.get('pay_token'),
                },
                status=status.HTTP_201_CREATED
            )
        except RuntimeError as exc:
            logger.warning("Paiement refusé par hub Steeve: %s", exc)
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:  # pylint: disable=broad-except
            logger.exception("Erreur inattendue lors de l'initiation du paiement Steeve")
            return Response(
                {'error': 'Impossible d\'initier le paiement. Réessayez plus tard.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )


class PaymentStatusView(APIView):
    """
    GET /payments/status/<hub_reference>/

    Vérifie le statut d'un paiement auprès du hub de Steeve.
    Requiert un token JWT valide.

    Steeve recommande de TOUJOURS vérifier le statut (ne pas se fier uniquement au webhook).
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, hub_reference):
        """Vérifie et retourne le statut du paiement identifié par hub_reference."""
        # Récupérer la transaction locale
        try:
            tx = SteevHubTransaction.objects.get(  # type: ignore
                hub_reference=hub_reference,
                payment_request__client=request.user.client
            )
        except SteevHubTransaction.DoesNotExist:  # type: ignore # pylint: disable=no-member
            return Response(
                {'error': 'Transaction introuvable.'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Si déjà finalisée, retourner directement le statut local
        if tx.status in ('SUCCESS', 'FAILED'):
            return Response({'status': tx.status, 'hub_reference': hub_reference})

        # Interroger le hub de Steeve pour le statut à jour
        hub_status = check_steeve_payment_status(hub_reference)
        current_status = hub_status.get('status', 'UNKNOWN').upper()

        # Mettre à jour et traiter si le paiement vient de réussir
        if current_status in ('SUCCESS', 'SUCCESSFULL') and tx.status != 'SUCCESS':
            tx.status = 'SUCCESS'
            tx.save()
            try:
                handle_payment_success(tx)
                logger.info("Paiement confirmé via polling — ref=%s", hub_reference)
            except Exception:  # pylint: disable=broad-except
                logger.exception("Erreur activation licence après polling — ref=%s", hub_reference)

        elif current_status == 'FAILED' and tx.status != 'FAILED':
            tx.status = 'FAILED'
            tx.save()
            payment_request = tx.payment_request
            payment_request.statut = PaymentRequest.StatutPaiement.REJETE
            payment_request.save()

        return Response({'status': tx.status, 'hub_reference': hub_reference})


@method_decorator(csrf_exempt, name='dispatch')
class SteevHubWebhookView(APIView):
    """
    POST /payments/webhook/

    Endpoint appelé par le hub de Steeve pour signaler les changements de statut.
    Aucune authentification JWT requise (appelé par les serveurs de Steeve).

    Pour les tests en local : utiliser ngrok pour exposer ce endpoint publiquement.
    URL à donner à Steeve : https://<votre-ngrok>.ngrok-free.app/api/payments/webhook/
    """
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def post(self, request):
        """Traite les notifications de paiement reçues depuis le hub de Steeve."""
        logger.debug("Webhook Steeve reçu — Headers: %s", dict(request.headers))

        # 1. Vérification de la signature HMAC-SHA256
        signature = (
            request.headers.get('X-Webhook-Signature')
            or request.headers.get('X-Hub-Signature')
            or request.headers.get('X-Signature')
        )
        webhook_secret = getattr(settings, 'STEEVE_HUB_WEBHOOK_SECRET', None)

        if not webhook_secret:
            logger.error("STEEVE_HUB_WEBHOOK_SECRET non configuré — webhook rejeté.")
            return Response(
                {'error': 'Configuration webhook incomplète.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        if signature:
            expected = hmac.new(
                key=webhook_secret.encode('utf-8'),
                msg=request.body,
                digestmod=hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(expected, signature):
                logger.error("Signature webhook invalide ! Possible tentative de fraude.")
                return Response(
                    {'error': 'Signature invalide.'},
                    status=status.HTTP_403_FORBIDDEN
                )
        else:
            # Pas de signature = webhook_enabled probablement encore false côté Steeve
            # On log mais on continue (à sécuriser une fois les webhooks activés)
            logger.warning(
                "Webhook reçu sans signature (webhook_enabled peut-être false côté Steeve hub)."
            )

        # 2. Parsing du payload
        try:
            payload = json.loads(request.body)
        except (json.JSONDecodeError, ValueError):
            logger.error("Webhook Steeve — payload JSON invalide.")
            return Response({'error': 'Payload invalide.'}, status=status.HTTP_400_BAD_REQUEST)

        logger.debug("Payload Webhook Steeve: %s", payload)

        # 3. Extraction des données de paiement
        # Le payload suit la même structure que la réponse d'initiation
        payment_data = payload.get('payment', payload)
        hub_reference = payment_data.get('reference')
        new_status = str(payment_data.get('status', '')).upper()

        logger.info(
            "Webhook Steeve — ref=%s statut=%s",
            hub_reference, new_status
        )

        if not hub_reference:
            logger.warning("Webhook sans référence de paiement — ignoré.")
            return Response({'status': 'ignored'}, status=status.HTTP_200_OK)

        # 4. Récupérer la transaction
        try:
            tx = SteevHubTransaction.objects.get(  # type: ignore
                hub_reference=hub_reference
            )
        except SteevHubTransaction.DoesNotExist:  # type: ignore # pylint: disable=no-member
            logger.warning("Webhook: transaction introuvable pour ref=%s", hub_reference)
            # Retourner 200 pour éviter que Steeve hub ne réessaie indéfiniment
            return Response({'status': 'not_found'}, status=status.HTTP_200_OK)

        # 5. Idempotence — ignorer si déjà traité
        if tx.status == 'SUCCESS':
            logger.info("Webhook ignoré — paiement déjà traité (ref=%s)", hub_reference)
            return Response({'status': 'already_processed'}, status=status.HTTP_200_OK)

        # 6. Traitement selon le statut
        if new_status in ('SUCCESS', 'SUCCESSFULL'):
            tx.status = 'SUCCESS'
            tx.raw_response = payload
            tx.save()
            try:
                handle_payment_success(tx)
                logger.info("✅ Paiement activé via webhook — ref=%s", hub_reference)
            except Exception as exc:  # pylint: disable=broad-except
                logger.exception(
                    "Erreur activation licence via webhook ref=%s: %s",
                    hub_reference,
                    exc
                )
                return Response({'status': 'error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        elif new_status == 'FAILED':
            tx.status = 'FAILED'
            tx.raw_response = payload
            tx.save()
            # Rejeter aussi la PaymentRequest
            pr = tx.payment_request
            pr.statut = PaymentRequest.StatutPaiement.REJETE
            pr.save()
            logger.warning("❌ Paiement échoué via webhook — ref=%s", hub_reference)

        else:
            # Statut intermédiaire (PENDING, etc.) — on met à jour sans activer
            tx.status = new_status
            tx.raw_response = payload
            tx.save()
            logger.info("Statut intermédiaire reçu (%s) — ref=%s", new_status, hub_reference)

        return Response({'status': 'ok'}, status=status.HTTP_200_OK)
