# pyright: reportIncompatibleMethodOverride=false, reportIncompatibleVariableOverride=false
"""Serializers for the accounts application of ClariDoc Pro."""
from typing import Any, cast
from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import Client, Succursale, Licence, Fichier, Log, Machine, PaymentRequest, Visiteur

User = get_user_model()

class ClientSerializer(serializers.ModelSerializer):
    """Serializer for Client model."""
    class Meta:  # type: ignore[misc]
        """Meta options for ClientSerializer."""
        model = Client
        fields = '__all__'

class SuccursaleSerializer(serializers.ModelSerializer):
    """Serializer for Succursale model."""
    client_nom = serializers.CharField(source='client.nom', read_only=True)

    class Meta:  # type: ignore[misc]
        """Meta options for SuccursaleSerializer."""
        model = Succursale
        fields = '__all__'

class LicenceSerializer(serializers.ModelSerializer):
    """Serializer for Licence model."""
    succursale_nom = serializers.CharField(source='succursale.nom', read_only=True)

    class Meta:  # type: ignore[misc]
        """Meta options for LicenceSerializer."""
        model = Licence
        fields = '__all__'
        read_only_fields = ['cle_chiffree', 'aes_key_hex', 'iv_hex']

class MachineSerializer(serializers.ModelSerializer):
    """Serializer for Machine model."""
    class Meta:  # type: ignore[misc]
        """Meta options for MachineSerializer."""
        model = Machine
        fields = '__all__'

class PaymentRequestSerializer(serializers.ModelSerializer):
    """Serializer for PaymentRequest model."""
    client_nom = serializers.CharField(source='client.nom', read_only=True)
    succursale_cible_nom = serializers.CharField(source='succursale_cible.nom', read_only=True)

    class Meta:  # type: ignore[misc]
        """Meta options for PaymentRequestSerializer."""
        model = PaymentRequest
        fields = '__all__'
        read_only_fields = ['client', 'statut']

class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model including related names and password handling."""
    client_nom = serializers.StringRelatedField(source='client', read_only=True)
    succursale_nom = serializers.StringRelatedField(source='succursale', read_only=True)
    password = serializers.CharField(write_only=True, required=False)

    class Meta:  # type: ignore[misc]
        """Meta options for UserSerializer."""
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'role',
            'client', 'succursale', 'client_nom', 'succursale_nom', 'is_active', 'password'
        ]

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = super().create(validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        user = super().update(instance, validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Custom JWT Token serializer to include extra user info."""
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Ajouter des informations personnalisées au token
        token['username'] = user.username
        token['role'] = user.role
        if user.client:
            token['client_id'] = user.client.id
            token['client_code'] = user.client.code_client
        if user.succursale:
            token['succursale_id'] = user.succursale.id

        return token

    def validate(self, attrs):
        username = attrs.get("username")

        # Recherche par email si nécessaire
        if username and "@" in username:
            user_found = User.objects.filter(email__iexact=username).first()
            if user_found:
                username = user_found.username
                attrs["username"] = username
                print(f"DEBUG LOGIN: Mapping Email -> Username '{username}'")

        # Validation par SimpleJWT
        try:
            data = cast(dict[str, Any], super().validate(attrs))
            # AJOUTER les infos utilisateur (crucial pour le C#)
            data['user'] = UserSerializer(self.user).data
            return data
        except Exception as e:
            raise e

    def create(self, validated_data):
        """Not implemented for token serializer."""
        return None

    def update(self, instance, validated_data):
        """Not implemented for token serializer."""
        return None

class FichierSerializer(serializers.ModelSerializer):
    """Serializer for Fichier model."""
    user_nom = serializers.CharField(source='user.username', read_only=True)

    class Meta:  # type: ignore[misc]
        """Meta options for FichierSerializer."""
        model = Fichier
        fields = '__all__'
        read_only_fields = ['client', 'user', 'created_at']

class LogSerializer(serializers.ModelSerializer):
    """Serializer for Log model."""
    user_nom = serializers.CharField(source='user.username', read_only=True)
    client_nom = serializers.CharField(source='client.nom', read_only=True)

    # Le tri entre journal technique et activite privee du client ne se fait PAS
    # ici mais en amont, dans LogViewSet.get_queryset : un superadmin ne recoit
    # que les evenements de Log.ACTIONS_VISIBLES_SUPERADMIN. Masquer des champs
    # au sortir aurait vide les libelles dont il a justement besoin pour
    # diagnostiquer (« Connexion reussie depuis l'application Bureau. »).
    class Meta:  # type: ignore[misc]
        """Meta options for LogSerializer."""
        model = Log
        fields = '__all__'
        read_only_fields = ['client', 'user', 'created_at']

class VisiteurSerializer(serializers.ModelSerializer):
    """Serializer for Visiteur model."""
    client_nom = serializers.CharField(source='client.nom', read_only=True)
    succursale_nom = serializers.CharField(source='succursale.nom', read_only=True)
    # Libelle pret a afficher : evite au frontend et a l'appli C# de dupliquer
    # la table de correspondance.
    type_document_libelle = serializers.CharField(
        source='get_type_document_display', read_only=True, default=None
    )
    # Declare explicitement en CharField : le modele porte des `choices`, donc
    # ModelSerializer genererait un ChoiceField qui rejetterait 'cni_2024_recto'
    # AVANT validate_type_document. On accepte donc la valeur fine telle quelle
    # et on la normalise nous-memes.
    type_document = serializers.CharField(
        required=False, allow_null=True, allow_blank=True, max_length=40
    )

    class Meta:  # type: ignore[misc]
        """Meta options for VisiteurSerializer."""
        model = Visiteur
        fields = '__all__'
        read_only_fields = ['client', 'created_at']

    # Valeur FINE renvoyee par le moteur OCR -> categorie stockee.
    # La detection passeport s'appuie sur la MRZ TD3 validee par checksums
    # ICAO : c'est une preuve autoportante, donc fiable meme quand les champs
    # extraits sont mediocres.
    _PREFIXES_TYPE = (
        ('passeport', Visiteur.TypeDocument.PASSEPORT),
        ('passport', Visiteur.TypeDocument.PASSEPORT),
        ('cni', Visiteur.TypeDocument.CNI),
        ('carte', Visiteur.TypeDocument.CNI),
    )

    @classmethod
    def normaliser_type_document(cls, brut):
        """Ramene une valeur OCR quelconque aux trois categories du modele.

        Tolere None, la casse, les espaces, et les variantes fines
        ('cni_2024_verso', 'PASSEPORT', 'passeport_td3'...). Une valeur non
        reconnue mais NON VIDE devient AUTRE : une piece a bien ete presentee,
        c'est son type qui est indetermine. Une valeur vide reste None, ce qui
        distingue les visiteurs anterieurs au champ.
        """
        if brut is None:
            return None
        texte = str(brut).strip().lower()
        if not texte:
            return None
        # Deja normalise ?
        for valeur in Visiteur.TypeDocument.values:
            if texte == valeur.lower():
                return valeur
        for prefixe, categorie in cls._PREFIXES_TYPE:
            if texte.startswith(prefixe):
                return categorie
        return Visiteur.TypeDocument.AUTRE

    def validate_type_document(self, value):
        """Normalise a l'entree, quelle que soit la finesse envoyee par le client."""
        return self.normaliser_type_document(value)
