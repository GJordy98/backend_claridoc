# pyright: reportIncompatibleMethodOverride=false, reportIncompatibleVariableOverride=false
"""Serializers for the accounts application of ClariDoc Pro."""
from typing import Any, cast
from datetime import timedelta
from decimal import Decimal
from django.db import models, transaction
from django.utils import timezone
from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import (
    Client, Succursale, Licence, Fichier, Log, Machine, PaymentRequest, Visiteur,
    FicheHotel, FicheHotelAccompagnant, FicheHotelCoOccupant, ConfigFicheHotel,
    TicketCaisse, TicketCaisseLigne, ClotureCaisse
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
            'signee',
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
        # heure_sortie_prevue est calculee par le backend (date_arrivee + duree_heures) :
        # le client envoie uniquement duree_heures, jamais l'heure calculee.
        read_only_fields = ['client', 'annee', 'numero_fiche', 'heure_sortie_prevue', 'created_at']

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


# ── Tickets de caisse ─────────────────────────────────────────────────────────

def _tronquer_champs_texte(modele, donnees):
    """Coupe les chaînes trop longues à la taille de leur colonne.

    Le texte vient de l'OCR : une enseigne mal lue peut faire 400 caractères.
    Refuser le ticket (400) serait pire que de le tronquer, car la file de
    synchronisation du poste rejouerait indéfiniment un envoi refusé.
    """
    if not hasattr(donnees, 'items'):
        return donnees
    propre = dict(donnees.items())
    for champ in modele._meta.get_fields():  # pylint: disable=protected-access
        # CharField seulement : UUIDField annonce aussi max_length=32, et tronquer
        # un UUID de 36 caractères le rendrait invalide (ticket refusé en boucle).
        if not isinstance(champ, models.CharField):
            continue
        longueur = getattr(champ, 'max_length', None)
        valeur = propre.get(champ.name)
        if longueur and isinstance(valeur, str) and len(valeur) > longueur:
            propre[champ.name] = valeur[:longueur]
    return propre


class TicketCaisseLigneSerializer(serializers.ModelSerializer):
    """Ligne d'article d'un ticket de caisse."""

    class Meta:  # type: ignore[misc]
        """Meta options for TicketCaisseLigneSerializer."""
        model = TicketCaisseLigne
        fields = ['id', 'ordre', 'code', 'designation', 'quantite',
                  'prix_unitaire', 'remise', 'montant', 'tva']

    def to_internal_value(self, data):
        return super().to_internal_value(_tronquer_champs_texte(TicketCaisseLigne, data))


class TicketCaisseSerializer(serializers.ModelSerializer):
    """Ticket de caisse et ses lignes, écrits en un seul appel.

    Posés par le SERVEUR, jamais par le poste : la société cliente, la journée
    comptable, le contrôle de cohérence, l'auteur de la saisie et tout ce qui
    touche au contrôle (statut, contrôleur, date, commentaire — passent par
    l'action `controler`).
    """
    lignes = TicketCaisseLigneSerializer(many=True, required=False)
    succursale_nom = serializers.CharField(source='succursale.nom', read_only=True, default=None)
    saisi_par_nom = serializers.CharField(source='saisi_par.username', read_only=True, default=None)
    controle_par_nom = serializers.CharField(source='controle_par.username', read_only=True, default=None)
    type_ticket_libelle = serializers.CharField(source='get_type_ticket_display', read_only=True)
    statut_libelle = serializers.CharField(source='get_statut_display', read_only=True)
    ecart = serializers.SerializerMethodField()
    # Jour LOCAL de la saisie sur le poste (05/10/2026). Pas une colonne : il ne
    # sert qu'à poser la journée d'un ticket SANS date imprimée. Avant, cette
    # journée était le jour où le serveur RECEVAIT le ticket : saisi hors ligne
    # lundi, remonté mercredi, il manquait à la clôture de lundi.
    journee_saisie = serializers.DateField(write_only=True, required=False, allow_null=True)

    class Meta:  # type: ignore[misc]
        """Meta options for TicketCaisseSerializer."""
        model = TicketCaisse
        fields = '__all__'
        read_only_fields = [
            'client', 'journee', 'somme_articles', 'coherent', 'statut',
            'saisi_par', 'controle_par', 'date_controle', 'commentaire_controle',
            'apres_cloture', 'created_at', 'updated_at',
        ]
        # Texte OCR complet : ÉCRIT par le poste, JAMAIS renvoyé (décision du
        # 25/09/2026). C'est la transcription du ticket, presque le ticket
        # lui-même : il reste en base pour un litige, pas sur le portail.
        extra_kwargs = {'texte_ocr': {'write_only': True}}

    def get_ecart(self, obj):
        """Total imprimé − somme des articles (None si l'un des deux manque)."""
        if obj.total is None or obj.somme_articles is None:
            return None
        return obj.total - obj.somme_articles

    def to_internal_value(self, data):
        return super().to_internal_value(_tronquer_champs_texte(TicketCaisse, data))

    @staticmethod
    def _egal(a, b):
        """Même tolérance que le poste (TicketParser.Egal) : arrondis de caisse."""
        return abs(a - b) <= max(Decimal('1'), abs(b) * Decimal('0.005'))

    @staticmethod
    def _journee_saisie_plausible(journee_saisie):
        """Le jour de saisie annoncé par le poste, ou None s'il n'est pas crédible.

        Un jour d'avance est admis : le serveur compte en UTC, le poste en heure
        locale (UTC+1 au Cameroun), donc entre 23h et minuit le poste est déjà au
        lendemain. Au-delà, l'horloge du poste est fausse : on retombe sur le jour
        de réception plutôt que de ranger une recette dans le futur.
        """
        if journee_saisie is None:
            return None
        if journee_saisie > timezone.localdate() + timedelta(days=1):
            return None
        return journee_saisie

    @classmethod
    def recalculer(cls, ticket, journee_saisie=None):
        """Journée comptable + somme des articles + cohérence, puis sauvegarde.

        Journée : la date imprimée ; sinon le jour de saisie annoncé par le poste ;
        sinon (poste d'avant le 05/10/2026, ou horloge invraisemblable) le jour de
        réception.
        """
        ticket.journee = (ticket.date_ticket
                          or cls._journee_saisie_plausible(journee_saisie)
                          or timezone.localdate(ticket.created_at or timezone.now()))
        # Requête directe, pas ticket.lignes.all() : sur une mise à jour, la
        # relation peut être en cache (prefetch) et donner les ANCIENNES lignes.
        montants = [
            m for m in TicketCaisseLigne.objects.filter(ticket=ticket).values_list('montant', flat=True)
            if m is not None
        ]
        ticket.somme_articles = sum(montants, Decimal('0')) if montants else None

        if ticket.total is None or ticket.somme_articles is None:
            ticket.coherent = None
        else:
            somme, total = ticket.somme_articles, ticket.total
            remise = abs(ticket.remise_totale or 0)
            ticket.coherent = (
                cls._egal(somme, total)
                or (remise > 0 and cls._egal(somme - remise, total))
                or (ticket.sous_total is not None and cls._egal(somme, ticket.sous_total))
            )
        ticket.save(update_fields=['journee', 'somme_articles', 'coherent', 'updated_at'])
        return ticket

    @staticmethod
    def _ecrire_lignes(ticket, lignes):
        for i, ligne in enumerate(lignes):
            ligne.setdefault('ordre', i)
            TicketCaisseLigne.objects.create(ticket=ticket, **ligne)

    def create(self, validated_data):
        lignes = validated_data.pop('lignes', [])
        journee_saisie = validated_data.pop('journee_saisie', None)
        # journee est obligatoire en base : valeur provisoire, recalculée juste après.
        validated_data.setdefault('journee', validated_data.get('date_ticket') or timezone.localdate())
        with transaction.atomic():
            ticket = TicketCaisse.objects.create(**validated_data)
            self._ecrire_lignes(ticket, lignes)
            return self.recalculer(ticket, journee_saisie)

    def update(self, instance, validated_data):
        """Les lignes fournies REMPLACENT la liste ; absentes, elles sont conservées."""
        lignes = validated_data.pop('lignes', None)
        journee_saisie = validated_data.pop('journee_saisie', None)
        with transaction.atomic():
            for champ, valeur in validated_data.items():
                setattr(instance, champ, valeur)
            instance.save()
            if lignes is not None:
                instance.lignes.all().delete()
                self._ecrire_lignes(instance, lignes)
            # Correction sans jour de saisie : on garde la journée déjà retenue
            # plutôt que de retomber sur la date de création au serveur.
            if journee_saisie is None and not instance.date_ticket:
                journee_saisie = instance.journee
            return self.recalculer(instance, journee_saisie)


class ClotureCaisseSerializer(serializers.ModelSerializer):
    """Clôture de caisse d'une journée.

    Le poste n'envoie que `journee`, `especes_comptees` et `commentaire` : tout
    le reste — les totaux constatés, l'écart, l'auteur — est posé par le
    serveur. Un poste ne déclare pas lui-même ce que la caisse devait contenir.
    """
    cloture_par_nom = serializers.CharField(source='cloture_par.username', read_only=True, default=None)
    succursale_nom = serializers.CharField(source='succursale.nom', read_only=True, default=None)
    totaux_actuels = serializers.SerializerMethodField()
    desynchronise = serializers.SerializerMethodField()
    nb_tickets_apres_cloture = serializers.SerializerMethodField()
    # Validée ici plutôt que lue brute dans la vue : une date illisible donnait
    # une erreur 500 au lieu d'un refus clair.
    journee = serializers.DateField(
        required=False,
        input_formats=['%Y-%m-%d', '%d/%m/%Y'],
        error_messages={
            'invalid': "Date de journée invalide : attendue au format AAAA-MM-JJ (ex. 2026-10-15).",
        })

    class Meta:  # type: ignore[misc]
        """Meta options for ClotureCaisseSerializer."""
        model = ClotureCaisse
        fields = '__all__'
        read_only_fields = [
            'client', 'succursale', 'nb_tickets', 'total_ventes', 'total_achats',
            'total_attendu', 'ecart', 'cloture_par', 'date_cloture',
        ]

    @staticmethod
    def totaux_journee(client_id, succursale_id, journee):
        """Ce que les tickets de la journée annoncent EN CE MOMENT.

        Sert deux fois : pour figer les totaux à la clôture, et pour détecter
        ensuite qu'un ticket est arrivé en retard.
        """
        qs = TicketCaisse.objects.filter(client_id=client_id, journee=journee)
        if succursale_id is None:
            qs = qs.filter(succursale__isnull=True)
        else:
            qs = qs.filter(succursale_id=succursale_id)
        agg = qs.aggregate(
            nb=models.Count('id'),
            ventes=models.Sum('total', filter=models.Q(type_ticket=TicketCaisse.TypeTicket.VENTE)),
            achats=models.Sum('total', filter=models.Q(type_ticket=TicketCaisse.TypeTicket.ACHAT)),
        )
        ventes = agg['ventes'] or Decimal('0')
        achats = agg['achats'] or Decimal('0')
        return {
            'nb_tickets': agg['nb'] or 0,
            'total_ventes': ventes,
            'total_achats': achats,
            'total_attendu': ventes - achats,
        }

    def get_totaux_actuels(self, obj):
        """Recalcul à l'instant de la lecture — à comparer aux totaux figés."""
        return self.totaux_journee(obj.client_id, obj.succursale_id, obj.journee)

    def get_nb_tickets_apres_cloture(self, obj):
        """Tickets de la journée arrivés (ou déplacés) après la clôture : déjà
        comptés dans les totaux actualisés, signalés « en retard »."""
        qs = TicketCaisse.objects.filter(client_id=obj.client_id, journee=obj.journee,
                                         apres_cloture=True)
        if obj.succursale_id is None:
            return qs.filter(succursale__isnull=True).count()
        return qs.filter(succursale_id=obj.succursale_id).count()

    def get_desynchronise(self, obj):
        """Vrai si la journée ne dit plus la même chose que la clôture enregistrée.

        Depuis le 15/10/2026 la clôture est actualisée à chaque écriture de
        ticket : ce drapeau ne devrait plus se lever. Il reste comme filet de
        sécurité (écriture hors API, admin Django…).
        """
        actuels = self.get_totaux_actuels(obj)
        return (actuels['nb_tickets'] != obj.nb_tickets
                or actuels['total_attendu'] != obj.total_attendu)
