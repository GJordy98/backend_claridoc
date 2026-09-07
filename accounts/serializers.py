# pyright: reportIncompatibleMethodOverride=false, reportIncompatibleVariableOverride=false
"""Serializers for the accounts application of ClariDoc Pro."""
from typing import Any, cast
from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import (
    Client, Succursale, Licence, Fichier, Log, Machine, PaymentRequest, Visiteur,
    FicheHotel, FicheHotelAccompagnant, FicheHotelCoOccupant, ConfigFicheHotel
)

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


class FicheHotelAccompagnantSerializer(serializers.ModelSerializer):
    """Enfant de moins de quinze ans rattaché à une fiche d'entrée."""

    class Meta:  # type: ignore[misc]
        """Meta options for FicheHotelAccompagnantSerializer."""
        model = FicheHotelAccompagnant
        fields = ['id', 'nom', 'prenom', 'date_naissance', 'lieu_naissance', 'nationalite']


class FicheHotelCoOccupantSerializer(serializers.ModelSerializer):
    """Personne adulte (≥ 15 ans) co-occupant la chambre."""

    class Meta:  # type: ignore[misc]
        """Meta options for FicheHotelCoOccupantSerializer."""
        model = FicheHotelCoOccupant
        fields = [
            'id', 'nom', 'prenom', 'date_naissance',
            'lieu_naissance', 'nationalite', 'numero_identite', 'type_document',
        ]


class FicheHotelSerializer(serializers.ModelSerializer):
    """Fiche d'entrée hôtel, accompagnants et co-occupants compris.

    Les accompagnants et co-occupants sont écrits EN MÊME TEMPS que la fiche : le poste envoie
    un seul appel, et une fiche ne se retrouve jamais en base sans eux.
    """
    client_nom = serializers.CharField(source='client.nom', read_only=True)
    succursale_nom = serializers.CharField(source='succursale.nom', read_only=True)
    type_document_libelle = serializers.CharField(
        source='get_type_document_display', read_only=True, default=None
    )
    # Meme raison que pour VisiteurSerializer : le modele porte des `choices`,
    # donc ModelSerializer rejetterait 'cni_2024_recto' AVANT la normalisation.
    type_document = serializers.CharField(
        required=False, allow_null=True, allow_blank=True, max_length=40
    )
    accompagnants = FicheHotelAccompagnantSerializer(many=True, required=False)
    co_occupants = FicheHotelCoOccupantSerializer(many=True, required=False)
    # Reference imprimee sur la fiche et affichee au registre : « 2026-0142 ».
    reference = serializers.SerializerMethodField()

    class Meta:  # type: ignore[misc]
        """Meta options for FicheHotelSerializer."""
        model = FicheHotel
        fields = '__all__'
        # La numerotation est attribuee par le serveur (cf. FicheHotelViewSet) :
        # un poste ne peut ni la choisir ni la corriger.
        read_only_fields = ['client', 'annee', 'numero_fiche', 'created_at']

    def get_reference(self, obj):
        """Reference lisible de la fiche, telle qu'imprimee."""
        return f"{obj.annee}-{obj.numero_fiche:04d}"

    def validate_type_document(self, value):
        """Normalise la valeur fine du moteur OCR.

        Delegue a VisiteurSerializer : la table de correspondance reste unique
        pour toute l'application, et les deux circuits ne peuvent pas diverger.
        """
        return VisiteurSerializer.normaliser_type_document(value)

    def create(self, validated_data):
        """Cree la fiche, ses accompagnants et co-occupants en une seule transaction."""
        accompagnants = validated_data.pop('accompagnants', [])
        co_occupants = validated_data.pop('co_occupants', [])
        fiche = FicheHotel.objects.create(**validated_data)
        for enfant in accompagnants:
            FicheHotelAccompagnant.objects.create(fiche=fiche, **enfant)
        for co in co_occupants:
            FicheHotelCoOccupant.objects.create(fiche=fiche, **co)
        return fiche

    def update(self, instance, validated_data):
        """Met a jour la fiche ; les accompagnants et co_occupants fournis REMPLACENT la liste."""
        accompagnants = validated_data.pop('accompagnants', None)
        co_occupants = validated_data.pop('co_occupants', None)
        for champ, valeur in validated_data.items():
            setattr(instance, champ, valeur)
        instance.save()
        if accompagnants is not None:
            instance.accompagnants.all().delete()
            for enfant in accompagnants:
                FicheHotelAccompagnant.objects.create(fiche=instance, **enfant)
        if co_occupants is not None:
            instance.co_occupants.all().delete()
            for co in co_occupants:
                FicheHotelCoOccupant.objects.create(fiche=instance, **co)
        return instance


class ConfigFicheHotelSerializer(serializers.ModelSerializer):
    """Serializer pour la configuration et personnalisation de la fiche hôtel."""

    logo_url = serializers.SerializerMethodField()
    client_nom = serializers.CharField(source='client.nom', read_only=True)

    # Champs d'établissement configurables par défaut si non spécifiés
    CHAMPS_CONFIGURABLES_DEFAUT = [
        {"field": "chambre",
            "visible": True, "obligatoire": True, "ordre": 1, "libelle": "Numéro de chambre"},
        {"field": "sexe", "visible": True, "obligatoire": False, "ordre": 2, "libelle": "Sexe"},
        {"field": "profession",
            "visible": True, "obligatoire": False, "ordre": 3, "libelle": "Profession"},
        {"field": "numero_identite",
            "visible": True, "obligatoire": False, "ordre": 4, "libelle": "N° pièce d'identité"},
        {"field": "date_expiration",
            "visible": True, "obligatoire": False, "ordre": 5, "libelle": "Date d'expiration"},
        {"field": "nombre_personnes",
            "visible": True, "obligatoire": False, "ordre": 6, "libelle": "Nombre de personnes"},
        {"field": "motif_sejour",
            "visible": True, "obligatoire": False, "ordre": 7, "libelle": "Motif du séjour"},
        {"field": "provenance",
            "visible": True, "obligatoire": False, "ordre": 8, "libelle": "Provenance"},
        {"field": "destination",
            "visible": True, "obligatoire": False, "ordre": 9, "libelle": "Destination"},
        {"field": "telephone",
            "visible": True, "obligatoire": False, "ordre": 10, "libelle": "Téléphone"},
        {"field": "email", "visible": True, "obligatoire": False, "ordre": 11, "libelle": "E-mail"},
        {"field": "date_depart_prevue",
            "visible": True, "obligatoire": False, "ordre": 12, "libelle": "Date de départ prévue"},
        {"field": "type_document",
            "visible": True, "obligatoire": False, "ordre": 13, "libelle": "Type de document"},
        {"field": "accompagnants",
            "visible": True, "obligatoire": False,
            "ordre": 14, "libelle": "Accompagnants (-15 ans)"},
    ]

    class Meta:  # type: ignore[misc]
        """Meta options for ConfigFicheHotelSerializer."""
        model = ConfigFicheHotel
        fields = [
            'id', 'client', 'client_nom', 'logo', 'logo_url',
            'entete', 'pied_de_page', 'couleur_principale',
            'champs', 'updated_at'
        ]
        read_only_fields = ['id', 'client', 'updated_at']

    def get_logo_url(self, obj):
        """Retourne l'URL complète du logo si disponible."""
        if obj.logo and hasattr(obj.logo, 'url'):
            request = self.context.get('request')
            if request is not None:
                return request.build_absolute_uri(obj.logo.url)
            return obj.logo.url
        return None

    def to_representation(self, instance):
        """Si la liste des champs configurés est vide, renvoie la configuration par défaut."""
        data = super().to_representation(instance)
        if not data.get('champs'):
            data['champs'] = self.CHAMPS_CONFIGURABLES_DEFAUT
        return data
