"""Views for the accounts application of ClariDoc Pro."""
# pylint: disable=no-member,too-many-lines

import os
import random
import string
import sys
import uuid
from datetime import date as date_type

import django
import requests

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.db import transaction
from django.db.models import Count, Max, Q, Sum
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import (
    Client, Fichier, Licence, Log, Machine, PaymentRequest, Succursale,
    OTPVerification, Visiteur, FicheHotel, ConfigFicheHotel
)
from .serializers import (
    ClientSerializer, CustomTokenObtainPairSerializer, FichierSerializer,
    LicenceSerializer, LogSerializer, MachineSerializer, PaymentRequestSerializer,
    SuccursaleSerializer, UserSerializer, VisiteurSerializer, FicheHotelSerializer,
    ConfigFicheHotelSerializer
)
from .services import (
    cles_licence, decrypt_simple_string, encrypt_license_data,
    encrypt_simple_string, generate_aes_credentials,
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
            fiche = serializer.save(
                client=client, succursale=succursale,
                annee=annee, numero_fiche=dernier + 1,
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
        fiche = serializer.save()
        create_log(
            self.request.user,
            "FICHE_HOTEL_MODIF",
            f"Fiche d'entrée {fiche.annee}-{fiche.numero_fiche:04d} modifiée.",
            client=fiche.client,
            succursale=fiche.succursale,
        )

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
    """API de Sommaire Centralisée pour le Hub d'Administration d'Entreprise.
    

    Expose en un seul appel consolidé toutes les métriques métier, le registre d'activité,
    les erreurs/bugs récents, et l'état de santé du système pour le Hub Supervision.
    

    Authentification :
    - Via Token dans le header `X-Hub-Token` ou paramètre `?token=...`
    - OU via JWT utilisateur authentifié (SUPERADMIN, BOSS, ADMIN).
    """
    permission_classes = [permissions.AllowAny]

    def _est_autorise(self, request):
        token_env = os.environ.get('ADMIN_HUB_TOKEN', getattr(settings, 'STEEVE_HUB_TOKEN', ''))
        token_req = request.headers.get('X-Hub-Token') or request.query_params.get('token')
        if token_env and token_req and token_req.strip() == token_env.strip():
            return True
        if request.user and request.user.is_authenticated:
            role = getattr(request.user, 'role', '')
            if role in ('SUPERADMIN', 'BOSS', 'ADMIN') or request.user.is_superuser:
                return True
        # Si aucun token configuré en env, autoriser en mode dev si DEBUG=True
        if settings.DEBUG and not token_env:
            return True
        return False

    def get(self, request):
        """Retourne le sommaire consolidé du Hub d'Administration."""
        if not self._est_autorise(request):
            return Response(
                {"error": (
                    "Accès non autorisé au Hub d'Administration. "
                    "Fournissez un token X-Hub-Token valide ou connectez-vous."
                )},
                status=status.HTTP_403_FORBIDDEN
            )

        now = timezone.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        # ── 1. Métriques globales ───────────────────────────────────────────
        total_clients = Client.objects.count()
        active_clients = Client.objects.filter(is_active=True).count()
        total_succursales = Succursale.objects.count()
        total_users = User.objects.count()
        total_visiteurs = Visiteur.objects.count()
        total_fiches_hotel = FicheHotel.objects.count()
        total_fichiers = Fichier.objects.count()
        total_storage_bytes = Fichier.objects.aggregate(total=Sum('taille_octets'))['total'] or 0
        total_machines = Machine.objects.count()
        active_machines = Machine.objects.filter(is_active=True).count()
        pending_payments = PaymentRequest.objects.filter(
            statut=PaymentRequest.StatutPaiement.EN_ATTENTE
        ).count()

        # ── 2. Activité du jour ──────────────────────────────────────────────
        visiteurs_today = Visiteur.objects.filter(created_at__gte=today_start).count()
        fiches_hotel_today = FicheHotel.objects.filter(created_at__gte=today_start).count()
        fichiers_today = Fichier.objects.filter(created_at__gte=today_start).count()
        logs_today = Log.objects.filter(created_at__gte=today_start).count()

        # Filtre d'erreurs/bugs récents dans les logs
        error_filter = (
            Q(action__icontains='ERROR') |
            Q(action__icontains='FAIL') |
            Q(action__icontains='REJETE') |
            Q(action__icontains='EXPIRED') |
            Q(details__icontains='Exception') |
            Q(details__icontains='Error') |
            Q(details__icontains='Échec')
        )
        errors_today = Log.objects.filter(error_filter, created_at__gte=today_start).count()

        # ── 3. Derniers logs système (Audit) ──────────────────────────────────
        logs_qs = (
            Log.objects.select_related('user', 'client', 'succursale')
            .order_by('-created_at')[:25]
        )
        recent_logs = []
        for l in logs_qs:
            recent_logs.append({
                'id': l.id,
                'created_at': l.created_at.isoformat(),
                'action': l.action,
                'details': l.details,
                'nom_fichier': l.nom_fichier,
                'type_document': l.type_document,
                'user': l.user.username if l.user else None,
                'client': l.client.nom if l.client else None,
                'succursale': l.succursale.nom if l.succursale else None,
            })

        # ── 4. Registre des Erreurs & Warnings récents ───────────────────────
        error_logs_qs = (
            Log.objects.filter(error_filter)
            .select_related('user', 'client', 'succursale')
            .order_by('-created_at')[:20]
        )
        recent_errors = []
        for l in error_logs_qs:
            recent_errors.append({
                'id': l.id,
                'created_at': l.created_at.isoformat(),
                'action': l.action,
                'details': l.details,
                'user': l.user.username if l.user else None,
                'client': l.client.nom if l.client else None,
            })

        # ── 5. Synthèse par Client ───────────────────────────────────────────
        clients_qs = Client.objects.all().order_by('-created_at')
        clients_summary = []
        for c in clients_qs:
            licence_fin = None
            # Recherche de licence expirant la plus tard
            lics = Licence.objects.filter(succursale__client=c).order_by('-date_fin')
            if lics.exists():
                licence_fin = str(lics.first().date_fin)

            clients_summary.append({
                'id': c.id,
                'nom': c.nom,
                'code_client': c.code_client,
                'statut': c.statut,
                'is_active': c.is_active,
                'succursales_count': c.succursales.count(),
                'users_count': c.users.count(),
                'visiteurs_count': Visiteur.objects.filter(client=c).count(),
                'fiches_hotel_count': FicheHotel.objects.filter(client=c).count(),
                'licence_expiration': licence_fin,
            })

        # ── 6. État de Santé Système ─────────────────────────────────────────
        health_info = {
            'database': 'CONNECTED',
            'environment': 'production' if not settings.DEBUG else 'development',
            'debug_mode': settings.DEBUG,
            'python_version': (
                f"{sys.version_info.major}."
                f"{sys.version_info.minor}."
                f"{sys.version_info.micro}"
            ),
            'django_version': django.get_version(),
            'storage_mb': round(total_storage_bytes / (1024 * 1024), 2),
        }

        data = {
            'status': 'SUCCESS',
            'app_name': 'ClariDoc Pro Backend API',
            'version': '2.1.0',
            'timestamp': now.isoformat(),
            'system_health': health_info,
            'metrics': {
                'total_clients': total_clients,
                'active_clients': active_clients,
                'total_succursales': total_succursales,
                'total_users': total_users,
                'total_visiteurs': total_visiteurs,
                'total_fiches_hotel': total_fiches_hotel,
                'total_fichiers': total_fichiers,
                'total_storage_bytes': total_storage_bytes,
                'total_machines': total_machines,
                'active_machines': active_machines,
                'pending_payments': pending_payments,
            },
            'today_activity': {
                'visiteurs_today': visiteurs_today,
                'fiches_hotel_today': fiches_hotel_today,
                'fichiers_today': fichiers_today,
                'logs_today': logs_today,
                'errors_today': errors_today,
            },
            'recent_logs': recent_logs,
            'system_errors_and_alerts': recent_errors,
            'clients_summary': clients_summary,
        }

        return Response(data, status=status.HTTP_200_OK)
