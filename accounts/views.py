"""Views for the accounts application of ClariDoc Pro."""
# pylint: disable=no-member,too-many-lines

import os
import random
import string
import uuid
from datetime import date as date_type, timedelta

import requests

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.db import transaction
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.models import Count, Max, Min, Q, Sum
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import (
    Client, Fichier, Licence, Log, Machine, PaymentRequest, Succursale,
    OTPVerification, Visiteur, FicheHotel, ConfigFicheHotel, TicketCaisse, ClotureCaisse
)
from .serializers import (
    ClientSerializer, CustomTokenObtainPairSerializer, FichierSerializer,
    LicenceSerializer, LogSerializer, MachineSerializer, PaymentRequestSerializer,
    SuccursaleSerializer, UserSerializer, VisiteurSerializer, FicheHotelSerializer,
    ConfigFicheHotelSerializer, TicketCaisseSerializer, ClotureCaisseSerializer
)
from .services import (
    encrypt_license_data, generate_aes_credentials,
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

        payload = {
            'client_id': client.id,
            'max_postes': licence.max_machines,
            'expiration': licence.date_fin.strftime('%Y-%m-%d'),
            'plan': plan_forfait,
            'forfait_postes': forfait_postes,
            # La charge utile ne porte plus AUCUNE donnee de serveur de fichiers :
            # elle voyageait jusqu'ici accompagnee de la cle qui la dechiffre.
            # L'application lit desormais cette configuration sur le reseau de
            # l'agence, avec la cle posee sur le poste par le technicien.
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
# La configuration du serveur de fichiers n'est plus servie ni modifiable par
# cette API (09/09/2026). Elle est posee sur place par le technicien ClariDoc,
# chiffree sur le reseau de l'agence, et ne remonte jamais ici : ni lecture, ni
# ecriture, ni mot de passe en clair renvoye a un navigateur.
# L'ancienne vue SuccursaleConfigView et sa route /config/ sont supprimees.

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


class FicheHotelPagination(PageNumberPagination):
    """Pagination du registre hôtel.

    50 fiches par page : assez pour couvrir un mois chargé d'un petit
    établissement en un seul appel, sans jamais renvoyer des milliers de
    lignes quand l'historique s'accumule.
    Le client peut ajuster via ?page_size= (plafonné à 200).
    """
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 200


class FicheHotelViewSet(viewsets.ModelViewSet):
    """Registre des fiches d'entrée d'un établissement hôtelier."""
    serializer_class = FicheHotelSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = FicheHotelPagination

    def get_queryset(self):
        user = self.request.user
        # Confidentialité : une fiche d'hôtel concentre plus de données
        # personnelles qu'une fiche visiteur (domicile, e-mail, enfants
        # mineurs). Le SUPERADMIN (opérateur ClariDoc) n'y a JAMAIS accès,
        # exactement comme pour les fichiers et les visiteurs.
        if user.role == 'SUPERADMIN':
            return FicheHotel.objects.none()
        if not user.client:
            return FicheHotel.objects.none()

        qs = FicheHotel.objects.filter(client=user.client).prefetch_related('accompagnants')

        # Filtres du registre : ?statut=EN_COURS, ?chambre=204, ?annee=2026
        statut = self.request.query_params.get('statut')
        if statut:
            qs = qs.filter(statut=statut)
        chambre = self.request.query_params.get('chambre')
        if chambre:
            # Recherche partielle : « 20 » trouve « 204 », « 204A », « 1204 »
            qs = qs.filter(chambre__icontains=chambre)
        annee = self.request.query_params.get('annee')
        if annee:
            qs = qs.filter(annee=annee)

        # Filtres de recherche par identité (insensible à la casse et aux
        # accents différents selon les claviers).
        nom = self.request.query_params.get('nom')
        if nom:
            qs = qs.filter(nom__icontains=nom)
        prenom = self.request.query_params.get('prenom')
        if prenom:
            qs = qs.filter(prenom__icontains=prenom)

        return qs.order_by('-date_arrivee')

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

        annee = timezone.now().year

        # Numérotation SÉRIALISÉE. Deux réceptions qui valident au même instant
        # ne doivent pas obtenir le même numéro : on verrouille la ligne du
        # client le temps de lire le dernier numéro et d'écrire le suivant.
        # unique_together sur (client, annee, numero_fiche) reste le garde-fou
        # si un jour ce verrou saute.
        with transaction.atomic():
            if client:
                Client.objects.select_for_update().filter(pk=client.pk).first()
            dernier = FicheHotel.objects.filter(
                client=client, annee=annee
            ).aggregate(Max('numero_fiche'))['numero_fiche__max'] or 0
            # Calcul de l'heure de sortie prévue pour les séjours horaires.
            # On repose le résultat en base pour que la requête d'alertes
            # reste un simple filtre sur un champ indexable, sans calcul
            # à la volée sur chaque ligne du registre.
            duree_h = serializer.validated_data.get('duree_heures')
            date_arrivee = serializer.validated_data.get('date_arrivee', timezone.now())
            heure_sortie = (date_arrivee + timedelta(hours=int(duree_h))) if duree_h else None

            fiche = serializer.save(
                client=client, succursale=succursale,
                annee=annee, numero_fiche=dernier + 1,
                heure_sortie_prevue=heure_sortie,
            )

        create_log(
            user,
            "FICHE_HOTEL_ENTREE",
            f"Fiche d'entrée {fiche.annee}-{fiche.numero_fiche:04d} — "
            f"{fiche.nom} {fiche.prenom} enregistrée.",
            client=client,
            succursale=succursale,
        )

    def perform_update(self, serializer):
        """Journalise les corrections : une fiche est un registre.

        L'opérateur peut corriger ce que l'OCR a mal lu, y compris après
        validation. La trace de la correction, elle, ne se perd pas.
        """
        # Recalculer heure_sortie_prevue si duree_heures a changé.
        duree_h = serializer.validated_data.get('duree_heures', serializer.instance.duree_heures)
        if duree_h:
            date_arrivee = serializer.validated_data.get(
                'date_arrivee', serializer.instance.date_arrivee
            )
            heure_sortie = date_arrivee + timedelta(hours=int(duree_h))
        else:
            heure_sortie = None
        fiche = serializer.save(heure_sortie_prevue=heure_sortie)
        create_log(
            self.request.user,
            "FICHE_HOTEL_MODIF",
            f"Fiche d'entrée {fiche.annee}-{fiche.numero_fiche:04d} modifiée.",
            client=fiche.client,
            succursale=fiche.succursale,
        )

    # url_path explicite : sans lui, DRF publie la route avec le nom de la
    # méthode (« alertes_horaires »), et l'URL appelée par le poste
    # (« alertes-horaires ») tombe sur la route de détail -> 404.
    @action(detail=False, methods=['get'], url_path='alertes-horaires')
    def alertes_horaires(self, request):
        """Fiches EN_COURS dont l'heure de sortie prévue approche ou est dépassée.

        Interrogée toutes les minutes par l'app C# desktop (USER / ADMIN).
        Paramètre `minutes_avant` (défaut 15) : remonte les fiches dont
        heure_sortie_prevue <= maintenant + minutes_avant.
        Les fiches dont l'heure est déjà dépassée sont incluses volontairement :
        elles restent en alerte tant que le départ n'est pas validé.
        """
        try:
            minutes_avant = int(request.query_params.get('minutes_avant', 15))
        except (ValueError, TypeError):
            minutes_avant = 15

        maintenant = timezone.now()
        limite = maintenant + timedelta(minutes=minutes_avant)

        qs = self.get_queryset().filter(
            statut=FicheHotel.StatutFiche.EN_COURS,
            heure_sortie_prevue__isnull=False,
            heure_sortie_prevue__lte=limite,
        )
        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def depart(self, request, pk=None):  # pylint: disable=unused-argument
        """Clôture le séjour : le client a quitté l'établissement.

        `date_depart_reelle` est FACULTATIF mais determinant. Le poste peut
        enregistrer un depart alors que le reseau est coupe et ne le remonter
        que plus tard : horodater ici avec timezone.now() daterait le depart de
        l'instant de la synchronisation, pas de celui ou le client a rendu sa
        chambre. Sur un registre tenu a des fins de police, l'ecart n'est pas
        cosmetique. Le poste envoie donc l'heure qu'il a constatee.

        Une date posterieure a maintenant est ignoree : elle ne peut venir que
        d'une horloge de poste dereglee, et une sortie dans le futur serait plus
        trompeuse qu'une sortie horodatee a la reception.
        """
        fiche = self.get_object()

        date_depart = timezone.now()
        date_brute = request.data.get('date_depart_reelle')
        if date_brute:
            date_fournie = parse_datetime(str(date_brute))
            if date_fournie is not None:
                if timezone.is_naive(date_fournie):
                    date_fournie = timezone.make_aware(date_fournie)
                if date_fournie <= date_depart:
                    date_depart = date_fournie

        fiche.date_depart_reelle = date_depart
        fiche.statut = FicheHotel.StatutFiche.TERMINE
        fiche.save()
        create_log(
            request.user,
            "FICHE_HOTEL_DEPART",
            f"Fiche d'entrée {fiche.annee}-{fiche.numero_fiche:04d} — "
            f"départ de {fiche.nom} {fiche.prenom}.",
            client=fiche.client,
            succursale=fiche.succursale,
        )
        return Response(self.get_serializer(fiche).data)


class ConfigFicheHotelView(APIView):
    """API de consultation et de modification de la configuration de la fiche hôtel.

    - GET: Accessible à tous les rôles du client (SUPERADMIN, BOSS, ADMIN, USER, GARDIEN).
    - PUT/PATCH/POST/DELETE: Réservé aux rôles d'administration (SUPERADMIN, BOSS, ADMIN).
    """
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [JSONParser, MultiPartParser, FormParser]

    def _get_client_and_config(self, request):
        user = request.user
        if user.role == 'SUPERADMIN':
            client_id = request.query_params.get('client_id') or request.data.get('client_id')
            if client_id:
                client = Client.objects.filter(id=client_id).first()
            else:
                client = user.client
        else:
            client = user.client

        if not client:
            return None, None

        config, _ = ConfigFicheHotel.objects.get_or_create(client=client)
        return client, config

    def _est_autorise_ecriture(self, user):
        """Vérifie si l'utilisateur peut modifier la configuration (SUPERADMIN, BOSS, ADMIN)."""
        return user.role in ('SUPERADMIN', 'BOSS', 'ADMIN')

    def get(self, request):
        """Récupère la configuration de la fiche hôtel pour le client de l'utilisateur."""
        _, config = self._get_client_and_config(request)
        if not config:
            return Response(
                {"error": "Aucun client associé à cet utilisateur."},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer = ConfigFicheHotelSerializer(config, context={'request': request})
        return Response(serializer.data)

    def put(self, request):
        """Met à jour entièrement la configuration de la fiche hôtel."""
        if not self._est_autorise_ecriture(request.user):
            return Response(
                {"error": (
                    "Seuls les rôles SUPERADMIN, BOSS et ADMIN"
                    " peuvent modifier la configuration."
                )},
                status=status.HTTP_403_FORBIDDEN
            )

        _, config = self._get_client_and_config(request)
        if not config:
            return Response(
                {"error": "Aucun client associé à cet utilisateur."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = ConfigFicheHotelSerializer(
            config, data=request.data, partial=False, context={'request': request}
        )
        if serializer.is_valid():
            serializer.save()
            create_log(
                request.user,
                "CONFIG_HOTEL_MODIF",
                f"Configuration de la fiche hôtel mise à jour pour {config.client.nom}.",
                client=config.client
            )
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        """Met à jour partiellement la configuration de la fiche hôtel."""
        if not self._est_autorise_ecriture(request.user):
            return Response(
                {"error": (
                    "Seuls les rôles SUPERADMIN, BOSS et ADMIN"
                    " peuvent modifier la configuration."
                )},
                status=status.HTTP_403_FORBIDDEN
            )

        _, config = self._get_client_and_config(request)
        if not config:
            return Response(
                {"error": "Aucun client associé à cet utilisateur."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = ConfigFicheHotelSerializer(
            config, data=request.data, partial=True, context={'request': request}
        )
        if serializer.is_valid():
            serializer.save()
            create_log(
                request.user,
                "CONFIG_HOTEL_MODIF",
                f"Configuration de la fiche hôtel mise à jour (partial) pour {config.client.nom}.",
                client=config.client
            )
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request):
        """Permet l'upload du logo de l'hôtel."""
        if not self._est_autorise_ecriture(request.user):
            return Response(
                {"error": "Seuls les rôles SUPERADMIN, BOSS et ADMIN peuvent modifier le logo."},
                status=status.HTTP_403_FORBIDDEN
            )

        _, config = self._get_client_and_config(request)
        if not config:
            return Response(
                {"error": "Aucun client associé à cet utilisateur."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if 'logo' not in request.FILES:
            return Response(
                {"error": "Aucun fichier 'logo' n'a été fourni."},
                status=status.HTTP_400_BAD_REQUEST
            )

        config.logo = request.FILES['logo']
        config.save()
        create_log(
            request.user,
            "CONFIG_HOTEL_LOGO",
            f"Nouveau logo de fiche hôtel téléversé pour {config.client.nom}.",
            client=config.client
        )
        serializer = ConfigFicheHotelSerializer(config, context={'request': request})
        return Response(serializer.data)

    def delete(self, request):
        """Supprime le logo de l'hôtel."""
        if not self._est_autorise_ecriture(request.user):
            return Response(
                {"error": "Seuls les rôles SUPERADMIN, BOSS et ADMIN peuvent supprimer le logo."},
                status=status.HTTP_403_FORBIDDEN
            )

        _, config = self._get_client_and_config(request)
        if not config:
            return Response(
                {"error": "Aucun client associé à cet utilisateur."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if config.logo:
            config.logo.delete(save=True)
            create_log(
                request.user,
                "CONFIG_HOTEL_LOGO_DELETE",
                f"Logo de la fiche hôtel supprimé pour {config.client.nom}.",
                client=config.client
            )

        serializer = ConfigFicheHotelSerializer(config, context={'request': request})
        return Response(serializer.data)


class HubSummaryView(APIView):
    """API de Sommaire Centralisée conforme au Contrat d'Observabilité de l'AdminHub.

    Expose en un seul appel consolidé :
    - Les métriques instantanées (clients, appareils, documents)
    - Les alertes système et licences
    - Les finances et abonnements avec MRR normalisé
    - Les données métier spécifiques à ClariDoc Pro

    Authentification :
    - Header `X-Hub-Token` comparé à settings.ADMINHUB_SECRET_TOKEN
    - OU paramètre d'URL `?token=...`
    - OU session utilisateur authentifié (SUPERADMIN, BOSS, ADMIN).
    """
    permission_classes = [permissions.AllowAny]

    def _est_autorise(self, request):
        token_env = (
            os.environ.get('ADMINHUB_SECRET_TOKEN')
            or getattr(settings, 'ADMINHUB_SECRET_TOKEN', None)
            or os.environ.get('ADMIN_HUB_TOKEN')
            or getattr(settings, 'STEEVE_HUB_TOKEN', None)
        )
        token_req = request.headers.get('X-Hub-Token') or request.query_params.get('token')
        if token_req and token_env and token_req.strip() == str(token_env).strip():
            return True
        if request.user and request.user.is_authenticated:
            role = getattr(request.user, 'role', '')
            if role in ('SUPERADMIN', 'BOSS', 'ADMIN') or request.user.is_superuser:
                return True
        # Mode développement : autoriser si aucun token n'est configuré en production
        if settings.DEBUG and not os.environ.get('ADMINHUB_SECRET_TOKEN'):
            return True
        return False

    def get(self, request):
        """Retourne le sommaire standardisé pour l'AdminHub."""
        if not self._est_autorise(request):
            return Response(
                {"error": (
                    "Accès non autorisé au Hub d'Administration. "
                    "Fournissez un token X-Hub-Token valide ou connectez-vous."
                )},
                status=status.HTTP_403_FORBIDDEN
            )

        now = timezone.now()
        today = now.date()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        last_24h = now - timedelta(hours=24)
        last_30d = now - timedelta(days=30)

        # ── 1. Clients & Utilisateurs ─────────────────────────────────────────
        total_clients = Client.objects.count()
        active_clients = Client.objects.filter(is_active=True).count()
        total_succursales = Succursale.objects.count()
        total_users = User.objects.count()

        active_users_24h = (
            Log.objects.filter(created_at__gte=last_24h).values('user').distinct().count()
        )
        if active_users_24h == 0:
            active_users_24h = User.objects.filter(is_active=True).count()

        total_inactive = total_clients - active_clients
        churn_rate_30d = round(total_inactive / total_clients, 2) if total_clients > 0 else 0.0
        new_subscribers_30d = Client.objects.filter(created_at__gte=last_30d).count()

        # ── 2. Métiers (Visiteurs, Fiches Hôtel, Fichiers, Machines) ────────────
        total_visiteurs = Visiteur.objects.count()
        total_fiches_hotel = FicheHotel.objects.count()
        fiches_hotel_en_cours = FicheHotel.objects.filter(
            statut=FicheHotel.StatutFiche.EN_COURS
        ).count()
        total_fichiers = Fichier.objects.count()
        total_storage_bytes = Fichier.objects.aggregate(total=Sum('taille_octets'))['total'] or 0
        total_machines = Machine.objects.count()
        active_machines = Machine.objects.filter(is_active=True).count()
        pending_payments = PaymentRequest.objects.filter(
            statut=PaymentRequest.StatutPaiement.EN_ATTENTE
        ).count()

        # Activité du jour
        visiteurs_today = Visiteur.objects.filter(created_at__gte=today_start).count()
        fiches_hotel_today = FicheHotel.objects.filter(created_at__gte=today_start).count()
        fichiers_today = Fichier.objects.filter(created_at__gte=today_start).count()
        logs_today = Log.objects.filter(created_at__gte=today_start).count()
        activity_today = fichiers_today + visiteurs_today + fiches_hotel_today + logs_today

        # ── 3. Finances & Abonnements (MRR normalisé) ──────────────────────────
        valid_payments = PaymentRequest.objects.filter(statut=PaymentRequest.StatutPaiement.VALIDE)

        monthly_data = valid_payments.filter(forfait_duree__icontains='Mensuel').aggregate(
            c=Count('id'), total=Sum('montant')
        )
        monthly_count = monthly_data['c'] or 0
        monthly_amount = int(monthly_data['total'] or 0)

        quarterly_data = valid_payments.filter(forfait_duree__icontains='Trimestriel').aggregate(
            c=Count('id'), total=Sum('montant')
        )
        quarterly_count = quarterly_data['c'] or 0
        quarterly_amount = int(quarterly_data['total'] or 0)

        semestrial_data = valid_payments.filter(forfait_duree__icontains='Semestriel').aggregate(
            c=Count('id'), total=Sum('montant')
        )
        semestrial_count = semestrial_data['c'] or 0
        semestrial_amount = int(semestrial_data['total'] or 0)

        annual_data = valid_payments.filter(forfait_duree__icontains='Annuel').aggregate(
            c=Count('id'), total=Sum('montant')
        )
        annual_count = annual_data['c'] or 0
        annual_amount = int(annual_data['total'] or 0)

        # Formule stricte du Hub : Mensuel + (Trimestriel / 3) + (Semestriel / 6) + (Annuel / 12)
        mrr_normalized = round(
            monthly_amount + (quarterly_amount / 3) + (semestrial_amount / 6) + (annual_amount / 12)
        )

        plans_qs = valid_payments.values('forfait_postes').annotate(count=Count('id'))
        plans = [{'name': p['forfait_postes'] or 'Standard', 'count': p['count']} for p in plans_qs]

        # ── 4. Alertes d'observabilité ─────────────────────────────────────────
        alerts = []
        # a) Licences expirant dans les 7 jours
        soon = today + timedelta(days=7)
        for lic in Licence.objects.filter(
            date_fin__gte=today, date_fin__lte=soon
        ).select_related('succursale__client'):
            client_nom = (
                lic.succursale.client.nom
                if (lic.succursale and lic.succursale.client)
                else (lic.succursale.nom if lic.succursale else 'Inconnu')
            )
            alerts.append({
                'severity': 'warning',
                'message': (
                    f"Licence pour {client_nom} expire le {lic.date_fin.strftime('%d/%m/%Y')}"
                ),
                'timestamp': now.isoformat()
            })

        # b) Demandes de paiement en attente
        if pending_payments > 0:
            alerts.append({
                'severity': 'info',
                'message': f"{pending_payments} demande(s) de paiement en attente de validation",
                'timestamp': now.isoformat()
            })

        # c) Licences échues
        licences_expirees = Licence.objects.filter(date_fin__lt=today).count()
        if licences_expirees > 0:
            alerts.append({
                'severity': 'warning',
                'message': f"{licences_expirees} licence(s) arrivée(s) à expiration",
                'timestamp': now.isoformat()
            })

        # Détermination du statut global
        status_system = 'healthy'
        if any(a['severity'] == 'critical' for a in alerts):
            status_system = 'down'
        elif any(a['severity'] == 'warning' for a in alerts):
            status_system = 'degraded'

        # ── 5. Payload conforme au Contrat d'Observabilité de l'AdminHub ────────
        payload = {
            "project_name": "ClariDoc Pro",
            "status": status_system,
            "last_updated": now.isoformat(),

            # 1. Métriques instantanées (affichées dans les cartes du Hub)
            "metrics": [
                {"label": "Clients actifs", "value": active_clients},
                {"label": "Appareils connectés", "value": active_machines},
                {"label": "Fichiers numérisés", "value": total_fichiers},
                {"label": "Fiches hôtel", "value": total_fiches_hotel},
                {"label": "Visiteurs", "value": total_visiteurs},
                {"label": "Taux de disponibilité", "value": 99.9, "unit": "%"}
            ],
            "active_users_24h": active_users_24h,
            "activity_today": activity_today,

            # 2. Alertes éventuelles (déclenche les badges sur le Hub)
            "alerts": alerts,

            # 3. Finances & Abonnements (pour calcul du MRR / CA global sur l'accueil)
            "subscription": {
                "active_subscribers": active_clients,
                "mrr_normalized": mrr_normalized,
                "currency": "XAF",
                "churn_rate_30d": churn_rate_30d,
                "new_subscribers_30d": new_subscribers_30d,
                "breakdown_by_period": {
                    "monthly":    {"count": monthly_count,    "raw_amount": monthly_amount},
                    "quarterly":  {"count": quarterly_count,  "raw_amount": quarterly_amount},
                    "semestrial": {"count": semestrial_count, "raw_amount": semestrial_amount},
                    "annual":     {"count": annual_count,     "raw_amount": annual_amount}
                },
                "plans": plans
            },

            # 4. Données spécifiques métier (onglet dédié ClariDoc)
            "project_specific": {
                "kind": "claridoc",
                "total_clients": total_clients,
                "active_clients": active_clients,
                "total_succursales": total_succursales,
                "total_users": total_users,
                "total_fichiers": total_fichiers,
                "scans_today": fichiers_today,
                "fiches_hotel_total": total_fiches_hotel,
                "fiches_hotel_en_cours": fiches_hotel_en_cours,
                "fiches_hotel_today": fiches_hotel_today,
                "visiteurs_total": total_visiteurs,
                "visiteurs_today": visiteurs_today,
                "total_machines": total_machines,
                "active_machines": active_machines,
                "pending_payments": pending_payments,
                "storage_mb": round(total_storage_bytes / (1024 * 1024), 2)
            }
        }

        return Response(payload, status=status.HTTP_200_OK)


# ── Tickets de caisse ─────────────────────────────────────────────────────────

class PeutGererTickets(permissions.BasePermission):
    """Circuit des tickets de caisse (décision du 25/09/2026).

    USER        — enregistre, voit et corrige SES tickets tant qu'ils ne sont
                  pas contrôlés ;
    ADMIN/BOSS  — voient et contrôlent TOUS les tickets du client, lisent le
                  récapitulatif ;
    BOSS seul   — supprime.
    GARDIEN et SUPERADMIN : aucun accès (le superadmin ne voit jamais les
    données commerciales d'un client).
    """
    message = "Ce compte n'a pas accès aux tickets de caisse."

    ROLES_ACCES = ('BOSS', 'ADMIN', 'USER')
    ROLES_CONTROLE = ('BOSS', 'ADMIN')
    ACTIONS_CONTROLE = ('controler', 'resume')

    def has_permission(self, request, view):
        user = request.user
        if not (user and user.is_authenticated and user.client_id and user.role in self.ROLES_ACCES):
            return False
        if view.action == 'destroy':
            self.message = "Seul le chef d'entreprise peut supprimer un ticket enregistré."
            return user.role == 'BOSS'
        if view.action in self.ACTIONS_CONTROLE:
            self.message = ("Le contrôle des tickets est réservé à l'administrateur "
                            "et au chef d'entreprise.")
            return user.role in self.ROLES_CONTROLE
        return True

    def has_object_permission(self, request, view, obj):
        user = request.user
        if user.role in self.ROLES_CONTROLE:
            return True
        # USER : ses propres tickets, et plus de correction une fois contrôlés.
        if obj.saisi_par_id != user.id:
            return False
        if (request.method not in permissions.SAFE_METHODS
                and obj.statut == TicketCaisse.StatutTicket.CONTROLE):
            self.message = "Ce ticket a déjà été contrôlé : seul un administrateur peut le modifier."
            return False
        return True


class TicketCaissePagination(PageNumberPagination):
    """100 tickets par page (une journée de boutique tient en un appel)."""
    page_size = 100
    page_size_query_param = 'page_size'
    max_page_size = 500


class TicketCaisseViewSet(viewsets.ModelViewSet):
    """Tickets de caisse (ventes et achats) et récapitulatif de fin de journée."""
    serializer_class = TicketCaisseSerializer
    permission_classes = [permissions.IsAuthenticated, PeutGererTickets]
    pagination_class = TicketCaissePagination

    def get_queryset(self):
        user = self.request.user
        if user.role == 'SUPERADMIN' or not user.client_id:
            return TicketCaisse.objects.none()
        qs = (TicketCaisse.objects.filter(client_id=user.client_id)
              .select_related('succursale', 'saisi_par', 'controle_par')
              .prefetch_related('lignes'))
        if user.role == 'USER':
            qs = qs.filter(saisi_par=user)
        return self._filtrer(qs)

    def _filtrer(self, qs):
        """?journee= | ?date_debut=&date_fin=, ?type_ticket=, ?statut=,
        ?succursale=, ?saisi_par=, ?coherent=true|false, ?q= (enseigne, n°)."""
        p = self.request.query_params
        if p.get('journee'):
            qs = qs.filter(journee=p['journee'])
        if p.get('date_debut'):
            qs = qs.filter(journee__gte=p['date_debut'])
        if p.get('date_fin'):
            qs = qs.filter(journee__lte=p['date_fin'])
        if p.get('type_ticket'):
            qs = qs.filter(type_ticket=p['type_ticket'].upper())
        if p.get('statut'):
            qs = qs.filter(statut=p['statut'].upper())
        if p.get('succursale'):
            qs = qs.filter(succursale_id=p['succursale'])
        if p.get('saisi_par'):
            qs = qs.filter(saisi_par_id=p['saisi_par'])
        if p.get('coherent') in ('true', 'false'):
            qs = qs.filter(coherent=(p['coherent'] == 'true'))
        if p.get('q'):
            qs = qs.filter(Q(enseigne__icontains=p['q']) | Q(numero_ticket__icontains=p['q']))
        return qs

    @staticmethod
    def _reference(ticket):
        return ticket.numero_ticket or f"#{ticket.pk}"

    def create(self, request, *args, **kwargs):
        """Enregistrement idempotent : un `uid_poste` déjà connu renvoie le ticket existant.

        La file de synchronisation du poste rejoue les envois restés sans
        réponse ; créer un doublon doublerait le chiffre de la journée.
        """
        uid = request.data.get('uid_poste')
        if uid:
            try:
                existant = TicketCaisse.objects.filter(uid_poste=uid).first()
            except (ValueError, DjangoValidationError):
                existant = None
            if existant is not None:
                if existant.client_id != request.user.client_id:
                    return Response({"detail": "Identifiant de ticket déjà utilisé."},
                                    status=status.HTTP_409_CONFLICT)
                return Response(self.get_serializer(existant).data, status=status.HTTP_200_OK)
        return super().create(request, *args, **kwargs)

    @staticmethod
    def _cle_journee(ticket):
        return (ticket.client_id, ticket.succursale_id, ticket.journee)

    @staticmethod
    def _actualiser_cloture(cle):
        """Recalcule la clôture de la journée `cle`, s'il y en a une (règle du 15/10/2026).

        Les espèces comptées ne bougent pas ; les totaux, le nombre de tickets et
        l'écart suivent les tickets. Renvoie (clôture, ancien attendu) ou (None, None).
        """
        client_id, succursale_id, journee = cle
        cloture = ClotureCaisse.objects.filter(client_id=client_id, succursale_id=succursale_id,
                                               journee=journee).first()
        if cloture is None:
            return None, None
        avant = cloture.total_attendu
        totaux = ClotureCaisseSerializer.totaux_journee(client_id, succursale_id, journee)
        for champ, valeur in totaux.items():
            setattr(cloture, champ, valeur)
        cloture.ecart = (None if cloture.especes_comptees is None
                         else cloture.especes_comptees - totaux['total_attendu'])
        cloture.save(update_fields=list(totaux) + ['ecart'])
        return cloture, avant

    def _suivre_cloture(self, ticket, ancienne_cle=None):
        """Après une écriture : ticket arrivé dans une journée close = « en retard »
        et caisse actualisée ; journée quittée par le ticket actualisée aussi.
        Renvoie le complément de journal (vide si aucune clôture n'est touchée)."""
        cle = self._cle_journee(ticket)
        suite = ""
        cloture, avant = self._actualiser_cloture(cle)
        if cloture is not None:
            if ancienne_cle != cle and not ticket.apres_cloture:
                ticket.apres_cloture = True
                ticket.save(update_fields=['apres_cloture'])
            suite = (f" — APRÈS LA CLÔTURE du {ticket.journee} : caisse actualisée, attendu "
                     f"{avant} → {cloture.total_attendu}, écart {cloture.ecart}")
        if ancienne_cle is not None and ancienne_cle != cle:
            self._actualiser_cloture(ancienne_cle)
        return suite

    def perform_create(self, serializer):
        user = self.request.user
        ticket = serializer.save(client=user.client, succursale=user.succursale, saisi_par=user)
        # Un poste resté hors ligne peut remonter un ticket d'une journée déjà
        # clôturée : on l'ACCEPTE (le refuser ferait disparaître une recette et
        # bloquerait sa file de reprise), la caisse est actualisée et le ticket
        # marqué « en retard ».
        retard = self._suivre_cloture(ticket)
        create_log(
            user, "TICKET_CREE",
            f"Ticket {ticket.get_type_ticket_display().lower()} {self._reference(ticket)} "
            f"— total {ticket.total} {ticket.devise}{retard}.",
            client=ticket.client, succursale=ticket.succursale,
        )

    def _refuser_si_journee_close(self, ticket):
        """Interdit de retoucher un ticket d'une journée déjà clôturée.

        Un ticket EN RETARD reste accepté (voir ClotureCaisse) : ce n'est pas la
        même chose. Accepter une recette oubliée ne réécrit rien ; modifier ou
        supprimer après coup, si — l'écart signé ne correspondrait plus à ce qui
        a été compté. Le BOSS échappe au verrou, puisqu'il peut de toute façon
        rouvrir la journée.
        """
        if self.request.user.role == 'BOSS':
            return
        if ClotureCaisse.objects.filter(client_id=ticket.client_id,
                                        succursale_id=ticket.succursale_id,
                                        journee=ticket.journee).exists():
            raise PermissionDenied(
                f"La journée du {ticket.journee} est clôturée : ce ticket ne peut plus être "
                f"modifié. Demandez au chef d'entreprise de rouvrir la journée.")

    def perform_update(self, serializer):
        user = self.request.user
        self._refuser_si_journee_close(serializer.instance)
        ancienne_cle = self._cle_journee(serializer.instance)
        champs = {}
        # Une correction par le USER remet le ticket « à contrôler » : l'avis
        # d'anomalie portait sur l'ancienne version.
        if user.role == 'USER':
            champs = {'statut': TicketCaisse.StatutTicket.SAISI, 'controle_par': None,
                      'date_controle': None}
        ticket = serializer.save(**champs)
        # Une correction de date peut déplacer le ticket VERS une journée close :
        # accepté, caisse actualisée, ticket « en retard » (15/10/2026).
        retard = self._suivre_cloture(ticket, ancienne_cle)
        create_log(
            user, "TICKET_MODIFIE", f"Ticket {self._reference(ticket)} modifié{retard}.",
            client=ticket.client, succursale=ticket.succursale,
        )

    def perform_destroy(self, instance):
        self._refuser_si_journee_close(instance)
        cle = self._cle_journee(instance)
        create_log(
            self.request.user, "TICKET_SUPPRIME",
            f"Ticket {instance.get_type_ticket_display().lower()} {self._reference(instance)} "
            f"du {instance.journee} supprimé (total {instance.total} {instance.devise}).",
            client=instance.client, succursale=instance.succursale,
        )
        instance.delete()
        self._actualiser_cloture(cle)

    @action(detail=True, methods=['post'])
    def controler(self, request, pk=None):  # pylint: disable=unused-argument
        """ADMIN / BOSS : `statut` = CONTROLE (défaut) ou ANOMALIE, `commentaire` facultatif.

        Une anomalie sans commentaire est refusée : celui qui la corrige doit
        savoir ce qui ne va pas.
        """
        ticket = self.get_object()
        statut = str(request.data.get('statut') or TicketCaisse.StatutTicket.CONTROLE).upper()
        if statut not in (TicketCaisse.StatutTicket.CONTROLE, TicketCaisse.StatutTicket.ANOMALIE):
            return Response({"statut": "Valeurs possibles : CONTROLE, ANOMALIE."},
                            status=status.HTTP_400_BAD_REQUEST)
        commentaire = (request.data.get('commentaire') or '').strip()
        if statut == TicketCaisse.StatutTicket.ANOMALIE and not commentaire:
            return Response({"commentaire": "Décrivez l'anomalie constatée."},
                            status=status.HTTP_400_BAD_REQUEST)

        ticket.statut = statut
        ticket.controle_par = request.user
        ticket.date_controle = timezone.now()
        ticket.commentaire_controle = commentaire or None
        ticket.save(update_fields=['statut', 'controle_par', 'date_controle',
                                   'commentaire_controle', 'updated_at'])
        suite = f" — {commentaire}" if commentaire else ""
        create_log(
            request.user, "TICKET_CONTROLE",
            f"Ticket {self._reference(ticket)} : {ticket.get_statut_display().lower()}{suite}.",
            client=ticket.client, succursale=ticket.succursale,
        )
        return Response(self.get_serializer(ticket).data)

    @action(detail=False, methods=['get'])
    def resume(self, request):
        """Récapitulatif pour le contrôle de fin de journée (ADMIN / BOSS).

        Période : ?journee=AAAA-MM-JJ, ou ?date_debut=&date_fin= ; aujourd'hui
        par défaut. Mêmes filtres que la liste (?succursale=, ?type_ticket=…).
        Les montants sont ceux IMPRIMÉS sur les tickets (champ total).
        """
        p = request.query_params
        qs = self.get_queryset()
        if not (p.get('journee') or p.get('date_debut') or p.get('date_fin')):
            qs = qs.filter(journee=timezone.localdate())
        # Les agrégats n'ont pas besoin des lignes ni des jointures de la liste.
        qs = qs.prefetch_related(None).select_related(None)

        vente = Q(type_ticket=TicketCaisse.TypeTicket.VENTE)
        achat = Q(type_ticket=TicketCaisse.TypeTicket.ACHAT)

        def agregats():
            return {
                'nb_tickets': Count('id'),
                'nb_ventes': Count('id', filter=vente),
                'total_ventes': Sum('total', filter=vente),
                'nb_achats': Count('id', filter=achat),
                'total_achats': Sum('total', filter=achat),
            }

        def ventiler(*champs):
            return list(qs.values(*champs).annotate(**agregats()).order_by(*champs))

        global_ = qs.aggregate(
            **agregats(),
            a_controler=Count('id', filter=Q(statut=TicketCaisse.StatutTicket.SAISI)),
            controles=Count('id', filter=Q(statut=TicketCaisse.StatutTicket.CONTROLE)),
            anomalies=Count('id', filter=Q(statut=TicketCaisse.StatutTicket.ANOMALIE)),
            incoherents=Count('id', filter=Q(coherent=False)),
            sans_total=Count('id', filter=Q(total__isnull=True)),
        )
        bornes = qs.aggregate(debut=Min('journee'), fin=Max('journee'))
        aujourd_hui = timezone.localdate()
        return Response({
            'periode': {
                'debut': p.get('journee') or p.get('date_debut') or bornes['debut'] or aujourd_hui,
                'fin': p.get('journee') or p.get('date_fin') or bornes['fin'] or aujourd_hui,
            },
            'global': global_,
            'par_jour': ventiler('journee'),
            'par_mode_paiement': ventiler('type_ticket', 'mode_paiement'),
            'par_succursale': ventiler('succursale_id', 'succursale__nom'),
            'par_saisisseur': ventiler('saisi_par_id', 'saisi_par__username'),
        })


class PeutCloturerCaisse(permissions.BasePermission):
    """Clôture de caisse : ADMIN et BOSS la posent, le BOSS seul la rouvre.

    Le USER ne la voit même pas : il enregistre des tickets, il ne signe pas
    l'état de la caisse. GARDIEN et SUPERADMIN n'ont aucun accès, comme pour
    les tickets eux-mêmes.
    """
    message = "La clôture de caisse est réservée à l'administrateur et au chef d'entreprise."

    ROLES_ACCES = ('BOSS', 'ADMIN')

    def has_permission(self, request, view):
        user = request.user
        if not (user and user.is_authenticated and user.client_id and user.role in self.ROLES_ACCES):
            return False
        if view.action in ('destroy', 'rouvrir'):
            self.message = "Seul le chef d'entreprise peut rouvrir une journée clôturée."
            return user.role == 'BOSS'
        return True


class ClotureCaisseViewSet(viewsets.ModelViewSet):
    """Clôtures de caisse : une par journée et par succursale.

    Le poste envoie `journee`, `especes_comptees` et `commentaire`. Le serveur
    relève lui-même ce que les tickets annoncent et calcule l'écart : c'est le
    contrôle, il ne peut pas venir de la machine contrôlée.
    """
    serializer_class = ClotureCaisseSerializer
    permission_classes = [permissions.IsAuthenticated, PeutCloturerCaisse]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'SUPERADMIN' or not user.client_id:
            return ClotureCaisse.objects.none()
        qs = (ClotureCaisse.objects.filter(client_id=user.client_id)
              .select_related('succursale', 'cloture_par'))
        p = self.request.query_params
        if p.get('journee'):
            qs = qs.filter(journee=p['journee'])
        if p.get('date_debut'):
            qs = qs.filter(journee__gte=p['date_debut'])
        if p.get('date_fin'):
            qs = qs.filter(journee__lte=p['date_fin'])
        if p.get('succursale'):
            qs = qs.filter(succursale_id=p['succursale'])
        return qs

    @staticmethod
    def _succursale_demandee(request):
        """(succursale clôturée, réponse de refus ou None).

        Clé `succursale` ABSENTE : celle du compte, comme avant le 05/10/2026.
        Présente : le BOSS choisit parmi les succursales de SA société (null =
        tickets sans succursale) ; un ADMIN ne peut nommer que la sienne. Sans ce
        choix, un BOSS sans succursale clôturait une caisse vide : attendu 0,
        écart égal aux espèces comptées.
        """
        user = request.user
        if 'succursale' not in request.data:
            return user.succursale, None
        valeur = request.data.get('succursale')
        if valeur in (None, ''):
            demandee = None
        else:
            try:
                demandee = Succursale.objects.filter(pk=int(valeur), client_id=user.client_id).first()
            except (TypeError, ValueError):
                demandee = None
            if demandee is None:
                return None, Response({"succursale": ["Succursale inconnue pour cette société."]},
                                      status=status.HTTP_400_BAD_REQUEST)
        if user.role != 'BOSS' and (demandee.pk if demandee else None) != user.succursale_id:
            return None, Response({"detail": "Seul le chef d'entreprise peut clôturer une autre succursale."},
                                  status=status.HTTP_403_FORBIDDEN)
        return demandee, None

    def create(self, request, *args, **kwargs):
        """Clôture la journée demandée (aujourd'hui par défaut).

        Refuse une seconde clôture : il faut rouvrir d'abord, sinon deux
        déclarations contradictoires coexisteraient pour la même caisse.
        """
        user = request.user
        # Validation AVANT toute requête : une date illisible lue brute faisait
        # planter le filtre ci-dessous (erreur 500). Le sérialiseur renvoie un
        # refus 400 qui dit quel format est attendu.
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        journee = serializer.validated_data.get('journee') or timezone.localdate()

        succursale, refus = self._succursale_demandee(request)
        if refus is not None:
            return refus
        succursale_id = succursale.pk if succursale else None

        if ClotureCaisse.objects.filter(client_id=user.client_id,
                                        succursale_id=succursale_id,
                                        journee=journee).exists():
            return Response(
                {"detail": f"La journée du {journee:%d/%m/%Y} est déjà clôturée. "
                           f"Rouvrez-la avant de la clôturer à nouveau."},
                status=status.HTTP_409_CONFLICT)

        totaux = ClotureCaisseSerializer.totaux_journee(user.client_id, succursale_id, journee)
        especes = serializer.validated_data.get('especes_comptees')
        ecart = None if especes is None else especes - totaux['total_attendu']

        cloture = serializer.save(
            client=user.client, succursale=succursale, journee=journee,
            cloture_par=user, ecart=ecart, **totaux)

        create_log(
            user, "CAISSE_CLOTUREE",
            f"Journée {cloture.journee} clôturée — attendu {cloture.total_attendu}, "
            f"compté {cloture.especes_comptees}, écart {cloture.ecart} "
            f"({cloture.nb_tickets} ticket(s)).",
            client=cloture.client, succursale=cloture.succursale,
        )
        return Response(self.get_serializer(cloture).data, status=status.HTTP_201_CREATED)

    def perform_destroy(self, instance):
        create_log(
            self.request.user, "CAISSE_ROUVERTE",
            f"Journée {instance.journee} rouverte (écart signé : {instance.ecart}).",
            client=instance.client, succursale=instance.succursale,
        )
        instance.delete()

    @action(detail=True, methods=['post'])
    def rouvrir(self, request, pk=None):  # pylint: disable=unused-argument
        """BOSS : lève le verrou de la journée. Équivaut au DELETE, nommé pour le poste."""
        cloture = self.get_object()
        self.perform_destroy(cloture)
        return Response(status=status.HTTP_204_NO_CONTENT)
