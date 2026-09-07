"""Views for the accounts application of ClariDoc Pro."""
# pylint: disable=no-member,too-many-lines

from datetime import date as date_type
import random
import string
import uuid

import requests

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.db.models import Count, Sum
from django.utils import timezone
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import (
    Client, Fichier, Licence, Log, Machine, PaymentRequest, Succursale,
    OTPVerification, Visiteur
)
from .serializers import (
    ClientSerializer, CustomTokenObtainPairSerializer, FichierSerializer,
    LicenceSerializer, LogSerializer, MachineSerializer, PaymentRequestSerializer,
    SuccursaleSerializer, UserSerializer, VisiteurSerializer
)
from .services import (
    cles_licence, decrypt_simple_string, encrypt_license_data,
    encrypt_simple_string, generate_aes_credentials, resoudre_config_ftp,
    send_otp_email
)

class LogPagination(PageNumberPagination):
    """Pagination for audit logs (30 items per page)."""
    page_size = 30
    page_size_query_param = 'page_size'
    max_page_size = 100



User = get_user_model()


class PeutGererFichiers(permissions.BasePermission):
    """Réserve les fichiers numérisés à tout le monde SAUF le GARDIEN."""
    message = "Ce compte ne gère pas les fichiers numérisés."

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.peut_gerer_fichiers)


def create_log(user, action_type, details="", client=None, succursale=None):
    """Create an audit log entry for the given user and action."""
    try:
        if not client and user and hasattr(user, 'client'):
            client = user.client
        if not succursale and user and hasattr(user, 'succursale'):
            succursale = user.succursale
        Log.objects.create(
            user=user,
            client=client,
            succursale=succursale,
            action=action_type,
            details=details
        )
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Failed to create log: {exc}")


class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom JWT login view that injects extra user data into the response."""

    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        """Handle POST login and log successful connections."""
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            username = request.data.get('username')
            user = User.objects.filter(username=username).first()
            if user:
                create_log(user, "LOGIN_WEB", "Connexion réussie au portail web.")
        return response


class UserViewSet(viewsets.ModelViewSet):
    """ViewSet for managing User accounts with role-based access control."""

    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = None  # Désactiver la pagination pour simplifier l'app C#

    def create(self, request, *args, **kwargs):
        """Refuse la création d'un compte que le demandeur n'a pas le droit de créer.

        Contrôle placé AVANT la validation du sérialiseur : l'API acceptait
        jusqu'ici n'importe quel `role` envoyé par n'importe quel compte
        authentifié — un USER pouvait donc se fabriquer un ADMIN, voire un
        SUPERADMIN. La table de référence est User.ROLES_CREABLES.
        """
        # Le rôle doit être fourni EXPLICITEMENT. Il y avait ici un repli sur
        # 'USER' : une requête arrivant sans rôle — ou avec un rôle laissé à sa
        # valeur par défaut par un client périmé — créait donc un compte
        # Utilisateur sans que rien ne le signale. C'est exactement ce qui est
        # arrivé au compte « jean » le 20/08/2026, créé en USER alors que le
        # rôle demandé était GARDIEN. Un compte sans rôle est désormais refusé.
        role_brut = request.data.get('role')
        if role_brut is None or not str(role_brut).strip():
            return Response(
                {"role": ["Le rôle du compte doit être fourni explicitement."]},
                status=status.HTTP_400_BAD_REQUEST
            )

        role_cible = str(role_brut).strip().upper()
        if role_cible not in User.RoleChoices.values:
            # Sans ce contrôle, un rôle inconnu (client périmé, faute de frappe)
            # tombait dans le test de permission ci-dessous et ressortait en 403
            # « votre rôle ne permet pas de créer un compte X » — message trompeur
            # pour ce qui est en réalité un rôle inexistant.
            return Response(
                {"role": [
                    f"Rôle inconnu « {role_cible} ». Rôles acceptés : "
                    + ", ".join(User.RoleChoices.values) + "."
                ]},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not request.user.peut_creer_role(role_cible):
            return Response(
                {"role": [
                    f"Votre rôle ({request.user.role}) ne permet pas de créer "
                    f"un compte « {role_cible} »."
                ]},
                status=status.HTTP_403_FORBIDDEN
            )
        return super().create(request, *args, **kwargs)

    def perform_create(self, serializer):
        """Create a user and assign client/succursale based on the requester's role."""
        user = self.request.user

        client_id = self.request.data.get('client')
        client = None

        if user.role == 'SUPERADMIN' and client_id:
            try:
                client = Client.objects.get(id=client_id)
            except Client.DoesNotExist:
                pass
        elif user.role in ('BOSS', 'ADMIN'):
            client = user.client

        succursale_id = self.request.data.get('succursale')
        succursale = None
        # Un ADMIN ne peuple QUE sa propre agence : sa succursale est imposée,
        # jamais lue depuis la requête (sinon il lui suffisait d'envoyer l'id
        # d'une autre agence du même client pour y placer un compte).
        if user.role == 'ADMIN':
            succursale = user.succursale
        elif succursale_id:
            try:
                succursale = Succursale.objects.get(id=succursale_id)
            except Succursale.DoesNotExist:
                pass

        nouveau = serializer.save(client=client, succursale=succursale)
        create_log(
            user,
            "USER_CREE",
            f"Compte {nouveau.username} créé avec le rôle {nouveau.role}.",
            client=client,
            succursale=succursale
        )

    def update(self, request, *args, **kwargs):
        """Interdit de PROMOUVOIR un compte vers un rôle qu'on ne peut pas créer.

        Sans ce garde-fou, la restriction posée à la création se contournait en
        deux temps : chaque compte se voit lui-même dans `get_queryset`, donc un
        USER ou un GARDIEN pouvait faire PATCH /users/<son id>/ {"role": "ADMIN"}.
        DRF route `partial_update` vers `update`, PATCH est donc couvert aussi.
        """
        cible = self.get_object()
        role_avant = cible.role

        role_demande = request.data.get('role')
        if role_demande is not None:
            role_demande = str(role_demande).strip().upper()
            if role_demande != role_avant \
                    and not request.user.peut_creer_role(role_demande):
                return Response(
                    {"role": [
                        f"Votre rôle ({request.user.role}) ne permet pas d'attribuer "
                        f"le rôle « {role_demande} »."
                    ]},
                    status=status.HTTP_403_FORBIDDEN
                )

        reponse = super().update(request, *args, **kwargs)

        # Un changement de rôle change ce que le compte voit dans l'application :
        # il doit être traçable. Seule la CRÉATION était journalisée jusqu'ici, si
        # bien qu'un rôle modifié après coup ne laissait aucune trace — or c'est le
        # journal d'audit qui a permis d'établir que le compte « jean » avait été
        # enregistré en USER ; il faut la même preuve pour les modifications.
        try:
            cible.refresh_from_db()
            if cible.role != role_avant:
                create_log(
                    request.user,
                    "USER_ROLE_MODIFIE",
                    f"Rôle du compte {cible.username} : {role_avant} → {cible.role}.",
                    client=cible.client,
                    succursale=cible.succursale
                )
        except Exception as exc:  # pylint: disable=broad-except
            print(f"Failed to log role change: {exc}")

        return reponse

    def get_queryset(self):
        """Return users visible to the requester based on their role,
        with optional client_id filter."""
        user = self.request.user
        if user.role == 'SUPERADMIN':
            qs = User.objects.all()
            client_id = self.request.query_params.get('client_id')
            if client_id:
                qs = qs.filter(client_id=client_id)
            return qs
        if user.role == 'BOSS':
            return User.objects.filter(client=user.client).exclude(id=user.id)
        if user.role == 'ADMIN':
            return User.objects.filter(succursale=user.succursale).exclude(id=user.id)
        return User.objects.filter(id=user.id)

    @action(detail=False, methods=['GET'])
    def me(self, request):
        """Return the profile of the currently authenticated user."""
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)

    @action(detail=False, methods=['POST'])
    def change_password(self, request):
        """Allow the authenticated user to update their own password."""
        user = request.user
        new_password = request.data.get('new_password')
        if not new_password:
            return Response(
                {"message": "Nouveau mot de passe manquant."},
                status=status.HTTP_400_BAD_REQUEST
            )
        user.set_password(new_password)
        user.save()
        return Response(
            {"message": "Mot de passe mis à jour avec succès."},
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=['POST'])
    def toggle_active(self, request, pk=None):  # pylint: disable=unused-argument
        """Toggle the is_active flag of a specific user."""
        user_to_toggle = self.get_object()
        if user_to_toggle == request.user or user_to_toggle.role == 'SUPERADMIN':
            return Response(
                {"message": "Action non autorisée."},
                status=status.HTTP_403_FORBIDDEN
            )
        user_to_toggle.is_active = not user_to_toggle.is_active
        user_to_toggle.save()
        status_text = "activé" if user_to_toggle.is_active else "bloqué"
        create_log(
            request.user,
            f"USER_{status_text.upper()}",
            f"Utilisateur {user_to_toggle.username} {status_text}.",
            client=user_to_toggle.client
        )
        return Response({"message": f"L'utilisateur a été {status_text}."})


class ClientViewSet(viewsets.ModelViewSet):
    """ViewSet for managing Client (company) records."""

    serializer_class = ClientSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Return clients visible to the requester."""
        if self.request.user.role == 'SUPERADMIN':
            return Client.objects.all()
        return Client.objects.filter(id=self.request.user.client_id)

    @action(detail=False, methods=['get'])
    def usage_stats(self, request):
        """Return scan volume statistics per client (SuperAdmin only)."""
        if request.user.role != 'SUPERADMIN':
            return Response({"detail": "Non autorisé"}, status=403)
        stats = Client.objects.annotate(
            total_scans=Count('fichiers'),
            total_volume=Sum('fichiers__taille_octets'),
            total_logs=Count('logs')
        ).values('id', 'nom', 'code_client', 'total_scans', 'total_volume', 'total_logs')
        return Response(stats)


class SuccursaleViewSet(viewsets.ModelViewSet):
    """ViewSet for managing Succursale (branch) records."""

    serializer_class = SuccursaleSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Return succursales visible to the requester, with optional client_id filter."""
        user = self.request.user
        if user.role == 'SUPERADMIN':
            qs = Succursale.objects.all()
            client_id = self.request.query_params.get('client_id')
            if client_id:
                qs = qs.filter(client_id=client_id)
            return qs
        if user.role == 'BOSS':
            return Succursale.objects.filter(client=user.client)
        if user.role == 'ADMIN':
            return Succursale.objects.filter(id=user.succursale_id)
        return Succursale.objects.none()


class LicenceViewSet(viewsets.ModelViewSet):
    """ViewSet for managing Licence records."""

    serializer_class = LicenceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Return licences visible to the requester, with optional client_id filter."""
        user = self.request.user
        if user.role == 'SUPERADMIN':
            qs = Licence.objects.select_related('succursale').all()
            client_id = self.request.query_params.get('client_id')
            if client_id:
                qs = qs.filter(succursale__client_id=client_id)
            return qs
        if user.client:
            return Licence.objects.filter(succursale__client=user.client)
        return Licence.objects.none()

    def perform_create(self, serializer):
        """Create a licence and generate AES credentials."""
        licence = serializer.save()
        aes_key, iv_key = generate_aes_credentials()
        client_code = licence.succursale.client.code_client if licence.succursale else 'UNKNOWN'
        payload = {
            "client_code": client_code,
            "max_machines": licence.max_machines,
            "date_fin": licence.date_fin.strftime("%Y-%m-%d")
        }
        licence.aes_key_hex = aes_key
        licence.iv_hex = iv_key
        licence.cle_chiffree = encrypt_license_data(payload, aes_key, iv_key)
        licence.save()



# =============================================================================
# ENDPOINT PUBLIC : Vérification de licence au démarrage de l'app C#
# POST /api/startup/verify/
# Body: { "code_client": "BNK-00001", "hardware_id": "XXXX-YYYY" }
# =============================================================================
class StartupVerifyView(APIView):
    """Public API view to verify a machine licence at application startup."""

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        """Verify licence validity and return AES credentials to the C# desktop app."""
        code_activation = (request.data.get('code_activation') or '').strip()
        hardware_id = (request.data.get('hardware_id') or '').strip()

        if not hardware_id:
            return Response(
                {'statut': 'ERREUR', 'message': 'Hardware ID manquant.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        licence = None

        # Cas 1: Première activation (Saisie du code par l'utilisateur)
        if code_activation:
            try:
                licence = Licence.objects.get(code_activation=code_activation)
            except Licence.DoesNotExist:
                return Response(
                    {'statut': 'CODE_INVALIDE',
                     'message': 'Code d\'activation invalide ou introuvable.'},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            # Cas 2: Démarrage habituel (vérification via Empreinte Matérielle)
            machines = (
                Machine.objects.filter(hwid=hardware_id, is_active=True)
                .select_related('licence')
            )
            if not machines.exists():
                return Response(
                    {'statut': 'MACHINE_INCONNUE',
                     'message': 'Poste non reconnu. Une activation est requise.'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            # Prioriser une licence non expirée s'il y a plusieurs liaisons actives
            machine = None
            for m in machines:
                if m.licence.date_fin >= timezone.now().date():
                    machine = m
                    break

            if not machine:
                machine = machines.first()  # Repli sur la première (expirée)

            licence = machine.licence

        # Vérifier que le client est toujours actif (si lié)
        if licence.succursale and licence.succursale.client:
            if not licence.succursale.client.is_active:
                return Response(
                    {'statut': 'CLIENT_INACTIF',
                     'message': 'Le compte de cette société est suspendu.'},
                    status=status.HTTP_403_FORBIDDEN
                )

        # Vérifier la date d'expiration
        if licence.date_fin < timezone.now().date():
            return Response({
                'statut': 'LICENCE_EXPIREE',
                'message': f'Licence expirée le {licence.date_fin.strftime("%d/%m/%Y")}.'
            }, status=status.HTTP_402_PAYMENT_REQUIRED)

        # Gérer la machine (Enregistrement si nouvelle machine)
        # Vérifier le quota AVANT la création pour éviter un enregistrement fantôme
        try:
            machine = Machine.objects.get(licence=licence, hwid=hardware_id)
            # Machine connue : vérifier si elle est active
            if not machine.is_active:
                return Response(
                    {'statut': 'MACHINE_BLOQUEE',
                     'message': 'Ce poste a été bloqué par l\'administrateur.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            # Mettre à jour la date de dernière connexion
            machine.save()
        except Machine.DoesNotExist:
            # Désactiver toute liaison existante de cet HWID
            # sur d'autres licences (pour libérer les quotas)
            Machine.objects.filter(
                hwid=hardware_id, is_active=True
            ).update(is_active=False)

            # Nouvelle machine : vérifier le quota avant d'enregistrer
            active_machines_count = Machine.objects.filter(licence=licence, is_active=True).count()
            if active_machines_count >= licence.max_machines:
                return Response(
                    {'statut': 'QUOTA_DEPASSE',
                     'message': f'Quota de postes maximum atteint ({licence.max_machines}).'},
                    status=status.HTTP_403_FORBIDDEN
                )
            machine = Machine.objects.create(licence=licence, hwid=hardware_id)

        # Tout est bon ! Génération de la clé chiffrée
        if not licence.aes_key_hex or not licence.iv_hex:
            aes, iv = generate_aes_credentials()
            licence.aes_key_hex = aes
            licence.iv_hex = iv

        if not licence.succursale or not licence.succursale.client:
            return Response(
                {'statut': 'LICENCE_INVALIDE',
                 'message': 'Cette licence est corrompue (aucune société associée).'},
                status=status.HTTP_400_BAD_REQUEST
            )

        client = licence.succursale.client
        succ = licence.succursale

        # Nom réel du forfait (durée : Mensuel / Annuel …) : issu de la dernière demande de
        # paiement VALIDÉE pour cette succursale. La durée de licence et le nombre de postes
        # découlent de ce forfait payé par le boss pour l'agence.
        forfait_pr = PaymentRequest.objects.filter(
            succursale_cible=succ, statut='VALIDE'
        ).order_by('-updated_at').first()
        plan_forfait = (
            forfait_pr.forfait_duree if (forfait_pr and forfait_pr.forfait_duree) else 'PREMIUM'
        )
        forfait_postes = (
            forfait_pr.forfait_postes if (forfait_pr and forfait_pr.forfait_postes) else ''
        )

        # Configuration FTP effective : celle de la succursale, ou a defaut celle
        # d'une autre agence du MEME CLIENT (rechiffree pour cette licence).
        # Sans ce repli, toute agence creee sans configuration FTP — le champ est
        # vide par defaut — livrait un mot de passe vide a l'application, qui
        # basculait hors-ligne en accusant le serveur de fichiers.
        cfg_ftp = resoudre_config_ftp(succ)

        payload = {
            'client_id': client.id,
            'max_postes': licence.max_machines,
            'expiration': licence.date_fin.strftime('%Y-%m-%d'),
            'plan': plan_forfait,
            'forfait_postes': forfait_postes,
            # Infos FTP pour la liaison locale
            'ftp_host': cfg_ftp['ftp_host'],
            'ftp_port': cfg_ftp['ftp_port'],
            'ftp_user': cfg_ftp['ftp_user'],
            'ftp_password_enc': cfg_ftp['ftp_password_enc'],
            'ftp_base_path': cfg_ftp['ftp_base_path'],
            'ftp_fingerprint': cfg_ftp['ftp_fingerprint'],
            # Aucune configuration FTP nulle part pour ce client : l'application
            # doit le DIRE, au lieu de laisser croire a un serveur en panne.
            'ftp_configuree': cfg_ftp['configuree']
        }
        licence.cle_chiffree = encrypt_license_data(payload, licence.aes_key_hex, licence.iv_hex)
        licence.save()

        # Renvoyer la clé chiffrée et les clés AES pour l'app C#
        return Response({
            'statut': 'VALIDE',
            'client_id': client.id,
            'client_nom': client.nom,
            'cle_chiffree': licence.cle_chiffree,
            'aes_key_hex': licence.aes_key_hex,
            'iv_hex': licence.iv_hex
        }, status=status.HTTP_200_OK)

class FichierViewSet(viewsets.ModelViewSet):
    """ViewSet for managing uploaded Fichier records."""

    serializer_class = FichierSerializer
    permission_classes = [permissions.IsAuthenticated, PeutGererFichiers]
    pagination_class = None

    def get_queryset(self):
        """Return files filtered by the requester's client scope."""
        user = self.request.user
        if user.role == 'SUPERADMIN':
            return Fichier.objects.none()
        queryset = Fichier.objects.filter(client_id=user.client_id)
        user_id = self.request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        return queryset.order_by('-created_at')

    def perform_create(self, serializer):
        """Save a file linked to the requesting user's client."""
        user = self.request.user
        serializer.save(user=user, client=user.client)

class LogViewSet(viewsets.ModelViewSet):
    """ViewSet for managing audit Log records."""

    serializer_class = LogSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = LogPagination

    def get_queryset(self):
        """Return logs filtered by role and optional query params."""
        user = self.request.user
        if user.role == 'SUPERADMIN':
            # Confidentialité : l'opérateur ClariDoc ne lit PAS l'activité de ses
            # clients — ni les scans (dont le libellé porte le nom du document), ni
            # les visiteurs. Il ne voit que les évènements de fonctionnement, définis
            # en liste blanche par Log.ACTIONS_VISIBLES_SUPERADMIN : tout ce qui n'y
            # figure pas est privé par défaut, y compris un futur type d'évènement.
            queryset = Log.objects.filter(Log.filtre_visible_superadmin())
        else:
            queryset = Log.objects.filter(client_id=user.client_id)

        user_id = self.request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(user_id=user_id)

        action_filter = self.request.query_params.get('action')
        if action_filter:
            queryset = queryset.filter(action__icontains=action_filter)

        client_id_filter = self.request.query_params.get('client_id')
        if client_id_filter:
            queryset = queryset.filter(client_id=client_id_filter)

        date_from = self.request.query_params.get('date_from')
        if date_from:
            queryset = queryset.filter(created_at__date__gte=date_from)

        date_to = self.request.query_params.get('date_to')
        if date_to:
            queryset = queryset.filter(created_at__date__lte=date_to)

        return queryset.order_by('-created_at')

    def perform_create(self, serializer):
        """Save a log linked to the requesting user's client."""
        user = self.request.user
        nom_fichier = self.request.data.get('nom_fichier', None)
        type_document = self.request.data.get('type_document', None)
        client = getattr(user, 'client', None)
        serializer.save(
            user=user,
            client=client,
            nom_fichier=nom_fichier,
            type_document=type_document
        )

    @action(detail=False, methods=['get'])
    def action_stats(self, request):
        """Return action volume grouped by client and action type (SuperAdmin only).

        Même liste blanche que le journal lui-même : ce décompte portait sinon
        l'activité privée des clients sous une autre forme (« SCAN_PDF : 143 »,
        « VISITEUR_ENTREE : 42 » pour telle société).
        """
        if request.user.role != 'SUPERADMIN':
            return Response({"detail": "Non autorisé"}, status=403)
        stats = (
            Log.objects.filter(Log.filtre_visible_superadmin())
            .values('client__id', 'client__nom', 'client__code_client', 'action')
            .annotate(count=Count('id'))
            .order_by('client__nom', 'action')
        )
        result = {}
        for row in stats:
            cid = row['client__id']
            if cid not in result:
                result[cid] = {
                    'client_id': cid,
                    'client_nom': row['client__nom'],
                    'code_client': row['client__code_client'],
                    'actions': {},
                    'total': 0
                }
            result[cid]['actions'][row['action']] = row['count']
            result[cid]['total'] += row['count']
        return Response(list(result.values()))

# =============================================================================
# ENDPOINT SUCCURSALE CONFIG (FTP)
# =============================================================================
class SuccursaleConfigView(APIView):
    """API view for reading and updating the FTP configuration of a Succursale."""

    permission_classes = [permissions.IsAuthenticated]

    def _get_target_succursale(self, user, request):
        """Resolve the target succursale from query params or user profile."""
        succ_id = request.query_params.get('succursale_id') or request.data.get('succursale_id')
        if succ_id:
            try:
                return Succursale.objects.get(id=succ_id, client=user.client)
            except Succursale.DoesNotExist:
                return None
        if user.succursale:
            return user.succursale
        if user.role == 'BOSS' and user.client:
            return user.client.succursales.first()
        return None

    def get(self, request):
        """Return the FTP configuration of the resolved succursale."""
        user = request.user
        succursale = self._get_target_succursale(user, request)
        if not succursale:
            return Response(
                {"message": "Aucune succursale associée ou trouvée."},
                status=status.HTTP_400_BAD_REQUEST
            )
        # Meme resolution que pour la payload de licence : l'ecran d'admin doit
        # montrer la configuration REELLEMENT utilisee par l'application, sinon
        # une agence qui fonctionne par heritage y apparaitrait vide.
        cfg = resoudre_config_ftp(succursale)

        # Le mot de passe est renvoye EN CLAIR, jamais chiffre.
        # L'ancien comportement renvoyait le texte chiffre dans un champ que le
        # PUT, lui, traite comme un mot de passe a chiffrer : un responsable qui
        # ouvrait la page et enregistrait sans toucher au champ rechiffrait donc
        # le chiffre, et le mot de passe devenait inutilisable en silence.
        # Le clair n'est expose qu'aux roles qui peuvent deja le MODIFIER.
        peut_voir = bool(user.client) and user.est_administrateur
        mot_de_passe = ''
        if peut_voir and cfg['ftp_password_enc']:
            aes, iv = cles_licence(succursale)
            if aes:
                try:
                    mot_de_passe = decrypt_simple_string(cfg['ftp_password_enc'], aes, iv)
                except Exception:  # pylint: disable=broad-except
                    mot_de_passe = ''

        return Response({
            "succursale_id": succursale.id,
            "ftp_host": cfg['ftp_host'],
            "ftp_port": cfg['ftp_port'],
            "ftp_user": cfg['ftp_user'],
            "ftp_password": mot_de_passe,
            "ftp_fingerprint": cfg['ftp_fingerprint'],
            "ftp_base_path": cfg['ftp_base_path'],
            "storage_mode": cfg['storage_mode'],
            # Diagnostic : d'ou vient cette configuration.
            "herite_de": cfg['herite_de'],
            "configuree": cfg['configuree']
        }, status=status.HTTP_200_OK)

    def put(self, request):
        """Update the FTP configuration of the resolved succursale."""
        user = request.user
        if not user.client or not user.est_administrateur:
            return Response(
                {"message": "Permissions insuffisantes."},
                status=status.HTTP_403_FORBIDDEN
            )
        succursale = self._get_target_succursale(user, request)
        if not succursale:
            return Response(
                {"message": "Aucune succursale associée ou trouvée."},
                status=status.HTTP_400_BAD_REQUEST
            )
        data = request.data
        if 'ftp_host' in data:
            succursale.ftp_host = data['ftp_host']
        if 'ftp_port' in data:
            succursale.ftp_port = data['ftp_port']
        if 'ftp_user' in data:
            succursale.ftp_user = data['ftp_user']
        # Deux champs aux sens DISTINCTS, pour lever l'ambiguite qui corrompait
        # le mot de passe :
        #   ftp_password     -> mot de passe EN CLAIR, chiffre ici (portail web)
        #   ftp_password_enc -> DEJA chiffre par l'appelant, stocke tel quel
        #                       (application C#, qui chiffre cote client dans
        #                        FormAdmin avant l'envoi)
        # Auparavant les deux clients ecrivaient dans ftp_password_enc, que cette
        # vue chiffrait systematiquement : le C# subissait donc un DOUBLE
        # chiffrement et le portail renvoyait le chiffre lu au GET.
        if 'ftp_password' in data:
            clair = data['ftp_password']
            if clair:
                aes, iv = cles_licence(succursale, creer=True)
                succursale.ftp_password_enc = (
                    encrypt_simple_string(clair, aes, iv) if aes else clair
                )
            else:
                succursale.ftp_password_enc = ""
        elif 'ftp_password_enc' in data:
            succursale.ftp_password_enc = data['ftp_password_enc'] or ""
        if 'ftp_fingerprint' in data:
            succursale.ftp_fingerprint = data['ftp_fingerprint']
        if 'ftp_base_path' in data:
            succursale.ftp_base_path = data['ftp_base_path']
        if 'storage_mode' in data:
            succursale.storage_mode = data['storage_mode']
        succursale.save()
        create_log(
            user, "CONFIG_UPDATE",
            f"Mise à jour de la configuration FTP pour {succursale.nom}.",
            client=succursale.client, succursale=succursale
        )
        return Response(
            {"message": "Configuration sauvegardée et sécurisée."},
            status=status.HTTP_200_OK
        )

# =============================================================================
# ENDPOINT MACHINES
# =============================================================================
class MachineViewSet(viewsets.ModelViewSet):
    """ViewSet for managing registered Machine (workstation) records."""

    serializer_class = MachineSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Return machines visible to the requester."""
        user = self.request.user
        if user.role == 'SUPERADMIN':
            return Machine.objects.all()
        if user.client:
            return Machine.objects.filter(licence__succursale__client=user.client)
        return Machine.objects.none()

    @action(detail=True, methods=['POST'])
    def toggle_active(self, request, pk=None):  # pylint: disable=unused-argument
        """Block or unblock a registered machine."""
        machine = self.get_object()
        machine.is_active = not machine.is_active
        machine.save()
        status_txt = "activé" if machine.is_active else "bloqué"
        create_log(
            request.user,
            f"MACHINE_{status_txt.upper()}",
            f"Poste {machine.hwid} {status_txt}.",
            client=machine.licence.succursale.client if machine.licence.succursale else None
        )
        return Response({"message": f"Le poste a été {status_txt}."}, status=status.HTTP_200_OK)

# =============================================================================
# ENDPOINT REGISTER (Public)
# =============================================================================

class RegisterView(APIView):
    """Public API view for new company self-registration."""

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        """Create a new Client and a BOSS user from registration form data."""
        data = request.data
        nom_societe  = data.get('nom_societe')
        first_name   = data.get('first_name')
        last_name    = data.get('last_name')
        email        = data.get('email')
        password     = data.get('password')
        telephone    = data.get('telephone')
        captcha_token = data.get('captcha_token')

        # CAPTCHA Validation (Cloudflare Turnstile)
        if settings.TURNSTILE_SECRET_KEY:
            if not captcha_token:
                return Response(
                    {"message": "La validation du CAPTCHA de sécurité est requise."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            try:
                verify_res = requests.post(
                    settings.TURNSTILE_VERIFY_URL,
                    data={
                        "secret": settings.TURNSTILE_SECRET_KEY,
                        "response": captcha_token,
                        "remoteip": request.META.get('REMOTE_ADDR')
                    },
                    timeout=5
                )
                verify_data = verify_res.json()
                if not verify_data.get("success"):
                    return Response(
                        {
                            "message": (
                                "Échec de validation du CAPTCHA de sécurité. "
                                "Veuillez réessayer."
                            )
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
            except (requests.RequestException, ValueError) as e:
                print(f"[CAPTCHA ERROR] {str(e)}")
                return Response(
                    {
                        "message": (
                            "Impossible de vérifier la sécurité CAPTCHA. "
                            "Veuillez réessayer plus tard."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

        if not all([nom_societe, first_name, last_name, email, password]):
            return Response(
                {"message": "Tous les champs (sauf téléphone) sont obligatoires."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if (
            User.objects.filter(email=email).exists()
            or User.objects.filter(username=email).exists()
        ):
            return Response(
                {"message": "Cet email est déjà utilisé."},
                status=status.HTTP_400_BAD_REQUEST
            )

        client = Client.objects.create(
            nom=nom_societe,
            code_client=str(uuid.uuid4())[:8].upper(),
            email_contact=email,
            telephone=telephone,
            statut=Client.StatutClient.SANS_LICENCE,
            is_active=False
        )

        User.objects.create_user(
            username=email,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            role='BOSS',
            client=client,
            is_active=False
        )

        otp_code = f"{random.randint(0, 999999):06d}"

        OTPVerification.objects.filter(email=email).delete()
        OTPVerification.objects.create(email=email, code=otp_code)

        # Envoi du code OTP par email via Brevo SMTP
        sent = send_otp_email(
            email=email,
            otp_code=otp_code,
            first_name=first_name,
        )
        if not sent:
            # Fallback console si l'envoi échoue (logs visibles côté serveur)
            print(f"[OTP FALLBACK] Code pour {email} : {otp_code}")

        return Response(
            {"message": "Inscription réussie. Un code de vérification a été envoyé par email.",
             "otp_required": True},
            status=status.HTTP_201_CREATED
        )

class VerifyOTPView(APIView):
    """Public API view to verify OTP and activate a user account."""

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        """Verify the OTP code and activate the user if valid."""
        email = request.data.get('email')
        code = request.data.get('code')

        if not email or not code:
            return Response(
                {"message": "Email et code sont requis."},
                status=status.HTTP_400_BAD_REQUEST
            )

        otp_record = OTPVerification.objects.filter(email=email).first()

        if not otp_record:
            return Response(
                {"message": "Aucun code OTP trouvé pour cet email."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not otp_record.is_valid():
            return Response(
                {"message": "Ce code OTP a expiré."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if otp_record.code != code:
            return Response(
                {"message": "Code OTP incorrect."},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = User.objects.filter(email=email).first()
        if user:
            user.is_active = True
            user.save()
            if user.client:
                user.client.is_active = True
                user.client.save()

        otp_record.delete()

        return Response({"message": "Compte activé avec succès."}, status=status.HTTP_200_OK)

# =============================================================================
# ENDPOINT PAYMENT REQUESTS
# =============================================================================

def generate_license_key():
    """Generate a licence activation key in the format CLD-XXXX-XXXX-XXXX."""
    chars = string.ascii_uppercase + string.digits

    def block():
        return ''.join(random.choices(chars, k=4))

    return f"CLD-{block()}-{block()}-{block()}"


class PaymentRequestViewSet(viewsets.ModelViewSet):
    """ViewSet for managing PaymentRequest records and licence generation."""

    serializer_class = PaymentRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Return payment requests visible to the requester."""
        user = self.request.user
        if user.role == 'SUPERADMIN':
            return PaymentRequest.objects.all().order_by('-created_at')
        return PaymentRequest.objects.filter(client=user.client).order_by('-created_at')

    def perform_create(self, serializer):
        """Save a payment request linked to the requesting user's client."""
        fichier = self.request.FILES.get('preuve_paiement_fichier')
        serializer.save(
            client=self.request.user.client,
            preuve_paiement_fichier=fichier if fichier else None
        )

    @action(detail=True, methods=['POST'])
    def validate(self, request, pk=None):  # pylint: disable=unused-argument
        """Validate or reject a pending payment request and generate a licence."""
        user = request.user
        if user.role != 'SUPERADMIN':
            return Response({"message": "Non autorisé."}, status=status.HTTP_403_FORBIDDEN)

        pr = self.get_object()
        if pr.statut != 'EN_ATTENTE':
            return Response(
                {"message": "Cette demande a déjà été traitée."},
                status=status.HTTP_400_BAD_REQUEST
            )

        decision = request.data.get('action')  # 'accept' ou 'reject'

        if decision == 'reject':
            pr.statut = 'REJETE'
            pr.save()
            return Response({"message": "Demande rejetée."})

        if decision == 'accept':
            # --- Paramètres saisis manuellement par le SuperAdmin ---
            max_machines = request.data.get('max_machines')
            date_fin_str = request.data.get('date_fin')
            montant_override = request.data.get('montant')

            if not max_machines or not date_fin_str:
                return Response(
                    {"message": "Le nombre de postes et la date de fin sont obligatoires."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                max_machines = int(max_machines)
                date_fin = date_type.fromisoformat(date_fin_str)
            except (ValueError, TypeError):
                return Response(
                    {"message": "Paramètres invalides "
                                "(max_machines entier, date_fin format YYYY-MM-DD)."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # --- Déterminer / créer la succursale ---
            if montant_override is not None:
                pr.montant = float(montant_override)
                pr.save()

            succursale = pr.succursale_cible
            if not succursale and pr.nom_nouvelle_succursale:
                succursale = Succursale.objects.create(
                    client=pr.client,
                    nom=pr.nom_nouvelle_succursale
                )
            elif not succursale:
                # Créer une succursale "Principale" par défaut
                succursale, _ = Succursale.objects.get_or_create(
                    client=pr.client,
                    nom="Principale"
                )

            # Fiabiliser le lien demande ↔ succursale (utile pour retrouver le forfait
            # d'une licence, y compris pour une nouvelle ouverture où succursale_cible
            # était null au départ).
            if pr.succursale_cible_id != succursale.id:
                pr.succursale_cible = succursale

            # --- Créer ou mettre à jour la licence ---
            licence, created = Licence.objects.get_or_create(
                succursale=succursale,
                defaults={'date_fin': date_fin}
            )
            if not created:
                licence.date_fin = date_fin

            licence.max_machines = max_machines

            # Générer les clés AES et le code d'activation si nécessaire
            if created or not licence.code_activation:
                aes_key_hex, iv_hex = generate_aes_credentials()
                licence.aes_key_hex = aes_key_hex
                licence.iv_hex = iv_hex
                licence.code_activation = generate_license_key()

            licence.save()

            # --- Activer le client s'il était SANS_LICENCE ---
            if pr.client.statut == 'SANS_LICENCE':
                pr.client.statut = 'ACTIF'
                pr.client.save()

            pr.statut = 'VALIDE'
            pr.save()

            create_log(
                user, "PAYMENT_VALIDATED",
                f"Paiement {pr.id} validé pour {pr.client.nom}. Licence générée.",
                client=pr.client
            )

            # --- Envoi email au BOSS du client ---
            boss_user = pr.client.users.filter(role='BOSS').first()
            boss_email = (boss_user.email if boss_user else None) or pr.client.email_contact
            email_envoye = False

            if boss_email:
                corps = (
                    f"Bonjour,\n\n"
                    f"Votre licence ClariDoc Pro a été activée avec succès.\n\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"  CODE D'ACTIVATION : {licence.code_activation}\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                    f"Détails de la licence :\n"
                    f"  • Nombre de postes autorisés : {licence.max_machines}\n"
                    f"  • Date d'expiration          : {licence.date_fin.strftime('%d/%m/%Y')}\n"
                    f"  • Succursale                 : {succursale.nom}\n\n"
                    f"Pour activer votre logiciel, lancez ClariDoc Pro et saisissez ce code\n"
                    f"lors du premier démarrage sur chaque poste.\n\n"
                    f"Cordialement,\nL'équipe ClariDoc"
                )
                send_mail(
                    subject='[ClariDoc Pro] Votre licence a été activée',
                    message=corps,
                    from_email=None,
                    recipient_list=[boss_email],
                    fail_silently=True,
                )
                email_envoye = True

            return Response({
                "message": "Paiement validé, licence générée.",
                "code_activation": licence.code_activation,
                "max_machines": licence.max_machines,
                "date_fin": licence.date_fin.strftime('%d/%m/%Y'),
                "client_nom": pr.client.nom,
                "succursale_nom": succursale.nom,
                "email_envoye_a": boss_email if email_envoye else None,
            }, status=status.HTTP_200_OK)

        return Response({"message": "Action invalide."}, status=status.HTTP_400_BAD_REQUEST)


class UniversalResetPasswordView(APIView):
    """Utility endpoint to reset any user password (dev/admin use only)."""

    permission_classes = [permissions.IsAdminUser]

    def get(self, _request, username, password):
        """Reset password for the given username or email."""
        user = User.objects.filter(username=username).first()
        if not user:
            user = User.objects.filter(email=username).first()
        if user:
            user.set_password(password)
            user.save()
            return Response(
                {"message": f"Mot de passe de '{user.username}' mis à jour avec succès !"}
            )
        return Response({"message": f"Utilisateur '{username}' non trouvé."}, status=404)

class VisiteurViewSet(viewsets.ModelViewSet):
    """ViewSet for managing Visiteur records."""
    serializer_class = VisiteurSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = None

    def get_queryset(self):
        user = self.request.user
        # Confidentialité : les données d'identité des visiteurs appartiennent au
        # client. Le SUPERADMIN (opérateur ClariDoc) n'y a JAMAIS accès, comme pour
        # les fichiers scannés (cf. FichierViewSet).
        # Aucun autre filtre de rôle ici : le registre reste ouvert à TOUS les rôles
        # du client (USER compris), le gardien s'y ajoute simplement.
        if user.role == 'SUPERADMIN':
            return Visiteur.objects.none()
        if user.client:
            qs = Visiteur.objects.filter(client=user.client)
        else:
            return Visiteur.objects.none()

        # Filtre optionnel par statut (?statut=PRESENT ou ?statut=PARTI)
        statut = self.request.query_params.get('statut')
        if statut:
            qs = qs.filter(statut=statut)

        # Ordre d'arrivée : du premier arrivé au dernier (chronologique).
        return qs.order_by('date_entree')

    def perform_create(self, serializer):
        user = self.request.user
        client = user.client
        succursale = user.succursale
        if user.role == 'SUPERADMIN':
            client_id = self.request.data.get('client')
            if client_id:
                client = Client.objects.filter(id=client_id).first()
            succursale_id = self.request.data.get('succursale')
            if succursale_id:
                succursale = Succursale.objects.filter(id=succursale_id).first()

        visiteur = serializer.save(client=client, succursale=succursale)
        create_log(
            user,
            "VISITEUR_ENTREE",
            f"Visiteur {visiteur.nom} {visiteur.prenom} enregistré en entrée.",
            client=client,
            succursale=succursale
        )

    @action(detail=True, methods=['post'])
    def sortie(self, request, pk=None):  # pylint: disable=unused-argument
        """Record visitor departure."""
        visiteur = self.get_object()
        visiteur.date_sortie = timezone.now()
        visiteur.statut = 'PARTI'
        visiteur.save()
        create_log(
            request.user,
            "VISITEUR_SORTIE",
            f"Visiteur {visiteur.nom} {visiteur.prenom} enregistré en sortie.",
            client=visiteur.client,
            succursale=visiteur.succursale
        )
        return Response({"message": "Sortie enregistrée avec succès."})
