"""
Models for the accounts application, defining Clients, Succursales, Users, and Licences.
"""
import datetime
from decimal import Decimal
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

class Client(models.Model):
    """
    Represents a corporate client using the ClariDoc Pro system.
    """
    nom = models.CharField(max_length=150)
    code_client = models.CharField(max_length=20, unique=True)
    email_contact = models.EmailField(null=True, blank=True)
    telephone = models.CharField(max_length=30, null=True, blank=True)
    is_active = models.BooleanField(default=True)

    objects = models.Manager()

    class StatutClient(models.TextChoices):
        """
        Choices for client status.
        """
        SANS_LICENCE = 'SANS_LICENCE', 'Sans Licence'
        ACTIF = 'ACTIF', 'Actif'
        SUSPENDU = 'SUSPENDU', 'Suspendu'

    statut = models.CharField(
        max_length=20,
        choices=StatutClient.choices,
        default=StatutClient.SANS_LICENCE
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.nom} ({self.code_client})"

class Succursale(models.Model):
    """
    Represents a branch or office belonging to a Client.
    Each branch has its own FTP configuration.
    """
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='succursales')
    nom = models.CharField(max_length=150)
    ville = models.CharField(max_length=100, null=True, blank=True)
    adresse = models.TextField(null=True, blank=True)

    # La configuration du serveur de fichiers (hote, compte, mot de passe, chemin)
    # NE VIT PLUS ICI depuis le 09/09/2026. Elle est deposee chiffree sur le
    # reseau de chaque agence et lue par les postes avec leur cle d'agence.
    #
    # Elle etait stockee ici et servie a l'application dans la charge utile de
    # licence AVEC la cle qui la dechiffre : le chiffrement en base ne protegeait
    # donc rien, et le portail exposait meme le mot de passe en clair. Le serveur
    # de fichiers appartient au reseau du client ; ses identifiants n'ont aucune
    # raison d'exister sur cette plateforme, ni d'etre modifiables depuis un
    # navigateur par un utilisateur non technique.
    #
    # Seule la LICENCE continue de venir d'ici.
    storage_mode = models.CharField(max_length=20, default='LOCAL')

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        # pylint: disable=no-member
        return f"{self.nom} - {self.client.nom}"

class User(AbstractUser):
    """
    Custom User model with roles and affiliation to Client and Succursale.
    """
    class RoleChoices(models.TextChoices):
        """
        Choices for user roles.
        """
        SUPERADMIN = 'SUPERADMIN', 'Super Admin ClariDoc'
        BOSS = 'BOSS', 'Chef d\'entreprise'
        ADMIN = 'ADMIN', 'Administrateur Succursale'
        USER = 'USER', 'Utilisateur (Scanner)'
        GARDIEN = 'GARDIEN', 'Gardien (Registre visiteurs)'

    # ── Groupes de rôles ────────────────────────────────────────────────────
    # USER et GARDIEN sont au MÊME niveau hiérarchique : deux métiers distincts
    # sans autorité l'un sur l'autre, et aucun des deux ne peut créer de compte.
    # La SEULE chose qui les sépare : le gardien n'a pas accès aux fichiers
    # numérisés — ils ne lui servent à rien, autant ne pas les lui exposer.
    #
    # Le registre des visiteurs, lui, n'est restreint pour PERSONNE : il reste
    # ouvert à tous les rôles, exactement comme avant l'arrivée du gardien.
    ROLES_ADMINISTRATION = ('SUPERADMIN', 'BOSS', 'ADMIN')
    ROLES_FICHIERS = ('SUPERADMIN', 'BOSS', 'ADMIN', 'USER')

    # Ce qu'un rôle a le droit de CRÉER comme comptes. Un ADMIN de succursale
    # peuple son agence en USER et GARDIEN, sans pouvoir se cloner ni fabriquer
    # un SUPERADMIN — c'était possible jusqu'ici, l'API acceptait n'importe quel
    # `role` envoyé par n'importe quel compte authentifié.
    ROLES_CREABLES = {
        'SUPERADMIN': ('SUPERADMIN', 'BOSS', 'ADMIN', 'USER', 'GARDIEN'),
        'BOSS': ('ADMIN', 'USER', 'GARDIEN'),
        'ADMIN': ('USER', 'GARDIEN'),
        'USER': (),
        'GARDIEN': (),
    }

    role = models.CharField(max_length=20, choices=RoleChoices.choices, default=RoleChoices.USER)
    client = models.ForeignKey(
        Client, on_delete=models.CASCADE, null=True, blank=True, related_name='users'
    )
    succursale = models.ForeignKey(
        Succursale, on_delete=models.SET_NULL, null=True, blank=True, related_name='users'
    )

    def __str__(self):
        # pylint: disable=no-member
        return f"{self.username} - {self.get_role_display()}"

    # ── Droits calculés (mêmes noms côté C# : SessionUtilisateur) ────────────
    @property
    def est_administrateur(self):
        """Vrai pour SUPERADMIN / BOSS / ADMIN : accès aux écrans d'administration."""
        return self.role in self.ROLES_ADMINISTRATION

    @property
    def peut_gerer_fichiers(self):
        """Vrai pour tous sauf GARDIEN : numérisation, galerie, historique."""
        return self.role in self.ROLES_FICHIERS

    def peut_creer_role(self, role_cible):
        """Dit si cet utilisateur a le droit de créer un compte de `role_cible`."""
        return role_cible in self.ROLES_CREABLES.get(self.role, ())

class Licence(models.Model):
    """
    License management for Succursales, controlling machine limits and activation.
    """
    succursale = models.OneToOneField(
        Succursale, on_delete=models.CASCADE, related_name='licence', null=True, blank=True
    )
    max_machines = models.IntegerField(default=1)
    date_fin = models.DateField()

    # Données cryptographiques générées automatiquement
    code_activation = models.CharField(max_length=50, null=True, blank=True, unique=True)
    cle_chiffree = models.TextField(null=True, blank=True)
    aes_key_hex = models.CharField(max_length=64, null=True, blank=True)
    iv_hex = models.CharField(max_length=32, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        # pylint: disable=no-member
        name = self.succursale.nom if self.succursale else 'Inconnue'
        return f"Licence {name} - Fin: {self.date_fin}"

class Machine(models.Model):
    """
    Represents a specific physical machine (HWID) registered under a Licence.
    """
    licence = models.ForeignKey(Licence, on_delete=models.CASCADE, related_name='machines')
    hwid = models.CharField(max_length=255)
    nom_machine = models.CharField(max_length=255, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    last_seen = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        """
        Meta options for Machine model.
        """
        unique_together = ('licence', 'hwid')

    def __str__(self):
        # pylint: disable=no-member
        name = 'Inconnue'
        if self.licence and self.licence.succursale:
            name = self.licence.succursale.nom
        return f"Machine {self.hwid} (Licence {name})"

    objects = models.Manager()

class Fichier(models.Model):
    """
    Represents a file uploaded to the system.
    """
    class StatutUpload(models.TextChoices):
        """
        Choices for file upload status.
        """
        EN_ATTENTE = 'EN_ATTENTE', 'En attente'
        VALIDE = 'VALIDE', 'Validé'          # Envoyé par l'app C# desktop
        SUCCES = 'SUCCES', 'Succès'
        ERREUR = 'ERREUR', 'Erreur'

    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='fichiers')
    succursale = models.ForeignKey(
        Succursale, on_delete=models.SET_NULL, null=True, blank=True, related_name='fichiers'
    )
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name='fichiers_uploades'
    )
    nom_fichier = models.CharField(max_length=255)
    type_fichier = models.CharField(max_length=50)
    taille_octets = models.BigIntegerField(default=0)
    dossier_logique = models.CharField(max_length=255, null=True, blank=True)
    hash_fichier = models.CharField(max_length=64, null=True, blank=True)
    statut_upload = models.CharField(
        max_length=20, choices=StatutUpload.choices, default=StatutUpload.EN_ATTENTE
    )
    chemin_ftp = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.nom_fichier} - {self.statut_upload}"

    objects = models.Manager()

class Log(models.Model):
    """
    Audit log for actions performed by users within the system.
    """

    # ── Ce que le SUPERADMIN (opérateur ClariDoc) a le droit de lire ────────
    # Règle produit : il ne voit RIEN de privé. Ni les fichiers, ni les visiteurs,
    # ni l'activité métier de ses clients. Il voit le FONCTIONNEMENT : qui se
    # connecte, quels comptes et quels postes existent, la configuration, les
    # paiements — de quoi exploiter le service et diagnostiquer une panne.
    #
    # C'est une LISTE BLANCHE de préfixes, volontairement : tout évènement qui
    # n'y figure pas est invisible pour ce rôle. Un nouveau type de log ajouté
    # plus tard est donc privé PAR DÉFAUT, et il faut un geste explicite ici
    # pour l'exposer. L'inverse (une liste noire) laisserait fuir le prochain
    # évènement métier que personne n'aura pensé à y ajouter.
    #
    # Exclus par construction : SCAN_* (le libellé porte le nom réel du document
    # numérisé) et VISITEUR_* (identités de visiteurs).
    ACTIONS_VISIBLES_SUPERADMIN = (
        'CONNEXION',      # ouverture de session sur l'application
        'DECONNEXION',
        'LOGIN',          # LOGIN_WEB : connexion au portail
        'LOGOUT',
        'USER_',          # USER_CREE, USER_ACTIVÉ, USER_BLOQUÉ
        'MACHINE_',       # MACHINE_ACTIVÉ, MACHINE_BLOQUÉ
        'CONFIG_',        # CONFIG_UPDATE
        'PAYMENT_',       # PAYMENT_VALIDATED
    )

    @classmethod
    def filtre_visible_superadmin(cls):
        """Filtre ne retenant que les évènements de fonctionnement.

        Utilisé PARTOUT où le superadmin lit le journal — la liste elle-même et
        les statistiques qui en dérivent. Deux portes sur la même donnée : sans
        ce point de passage unique, restreindre la liste laissait le décompte par
        type d'action (`action_stats`) annoncer « SCAN_PDF : 143 » pour un client.
        """
        filtre = models.Q()
        for prefixe in cls.ACTIONS_VISIBLES_SUPERADMIN:
            filtre |= models.Q(action__startswith=prefixe)
        return filtre
    client = models.ForeignKey(
        Client, on_delete=models.SET_NULL, related_name='logs', null=True, blank=True
    )
    succursale = models.ForeignKey(
        Succursale, on_delete=models.SET_NULL, null=True, blank=True, related_name='logs'
    )
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name='logs_actions'
    )
    action = models.CharField(max_length=255)
    details = models.TextField(null=True, blank=True)
    # Champs enrichis pour les actions ClariDoc desktop
    nom_fichier = models.CharField(
        max_length=500, null=True, blank=True, help_text="Nom du fichier concerné par l'action"
    )
    type_document = models.CharField(
        max_length=50, null=True, blank=True, help_text="Type du document (JPG, PDF, TIF, OCR...)"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.created_at}] {self.user} - {self.action}"

class PaymentRequest(models.Model):
    """
    Represents a request for payment (license renewal or new branch).
    """
    class StatutPaiement(models.TextChoices):
        """
        Choices for payment status.
        """
        EN_ATTENTE = 'EN_ATTENTE', 'En Attente'
        VALIDE = 'VALIDE', 'Validé'
        REJETE = 'REJETE', 'Rejeté'

    class MoyenPaiement(models.TextChoices):
        """
        Choices for payment methods.
        """
        NOTCHPAY = 'NOTCHPAY', 'Paiement Direct (NotchPay)'
        VIREMENT = 'VIREMENT', 'Virement Bancaire'
        MTN_MOMO = 'MTN_MOMO', 'MTN Mobile Money'
        ORANGE_MONEY = 'ORANGE_MONEY', 'Orange Money'
        AUTRE = 'AUTRE', 'Autre'

    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='payment_requests')
    succursale_cible = models.ForeignKey(
        Succursale, on_delete=models.SET_NULL, null=True, blank=True,
        help_text="Renseigné s'il s'agit d'un renouvellement."
    )
    nom_nouvelle_succursale = models.CharField(
        max_length=150, null=True, blank=True,
        help_text="Renseigné s'il s'agit d'une nouvelle ouverture."
    )

    forfait_duree = models.CharField(max_length=50) # ex: 'Mensuel', 'Annuel'
    forfait_postes = models.CharField(max_length=50) # ex: '1-3 PCs', '4-8 PCs'

    montant = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    moyen_paiement = models.CharField(max_length=50, choices=MoyenPaiement.choices)
    preuve_paiement_ref = models.CharField(
        max_length=255, null=True, blank=True, help_text="ID transaction ou lien vers capture"
    )
    preuve_paiement_fichier = models.FileField(
        upload_to='preuves_paiement/',
        null=True,
        blank=True,
        help_text="Capture d'écran ou PDF de la transaction (optionnel)"
    )

    statut = models.CharField(
        max_length=20, choices=StatutPaiement.choices, default=StatutPaiement.EN_ATTENTE
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = models.Manager()

    def __str__(self):
        # pylint: disable=no-member
        return f"Demande {self.id} - {self.client.nom} ({self.statut})"

class OTPVerification(models.Model):
    """
    Temporary OTP code for user registration validation.
    """
    email = models.EmailField(unique=True)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + datetime.timedelta(minutes=15)
        super().save(*args, **kwargs)

    def is_valid(self):
        """
        Checks if the OTP code is still within its validity period.
        """
        if not self.expires_at:
            return False
        return timezone.now() <= self.expires_at

    def __str__(self):
        return f"OTP for {self.email}"

class Visiteur(models.Model):
    """
    Represents a visitor registered at a client's premises.
    """
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='visiteurs')
    succursale = models.ForeignKey(
        Succursale, on_delete=models.SET_NULL, null=True, blank=True, related_name='visiteurs'
    )
    nom = models.CharField(max_length=150)
    prenom = models.CharField(max_length=150)
    date_naissance = models.DateField(null=True, blank=True)
    numero_identite = models.CharField(max_length=100, null=True, blank=True)
    nationalite = models.CharField(max_length=100, null=True, blank=True)
    entreprise_visitee = models.CharField(max_length=255, null=True, blank=True)
    date_entree = models.DateTimeField(default=timezone.now)
    date_sortie = models.DateTimeField(null=True, blank=True)
    photo_identite_chemin = models.TextField(null=True, blank=True)

    class StatutVisiteur(models.TextChoices):
        """Choices for visitor status."""
        PRESENT = 'PRESENT', 'Présent'
        PARTI = 'PARTI', 'Parti'

    statut = models.CharField(
        max_length=20,
        choices=StatutVisiteur.choices,
        default=StatutVisiteur.PRESENT
    )

    class TypeDocument(models.TextChoices):
        """Nature de la pièce d'identité présentée par le visiteur."""
        CNI = 'CNI', 'Carte nationale d\'identité'
        PASSEPORT = 'PASSEPORT', 'Passeport'
        AUTRE = 'AUTRE', 'Autre / non déterminé'

    # Le moteur OCR renvoie une valeur FINE ('passeport', 'cni_2016_recto',
    # 'cni_2024_verso'...). Elle est ramenée aux trois categories ci-dessus par
    # VisiteurSerializer.normaliser_type_document : le backend reste la
    # reference unique et tolere les ecarts de version entre postes clients.
    #
    # NULL = visiteur enregistre avant l'introduction du champ (juillet 2026),
    # a distinguer de AUTRE qui signifie « piece presentee, type indetermine ».
    type_document = models.CharField(
        max_length=20,
        choices=TypeDocument.choices,
        null=True,
        blank=True,
        db_index=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.nom} {self.prenom} - {self.statut}"

    objects = models.Manager()


class FicheHotel(models.Model):
    """Fiche d'entrée remplie à la réception d'un établissement hôtelier.

    Deux niveaux de champs, et la distinction compte :

    * le SOCLE STANDARD reprend la fiche individuelle de police dont le modèle
      est fixé par l'arrêté du 1er octobre 2015. Il est toujours rempli et
      toujours imprimé.
    * les CHAMPS D'ÉTABLISSEMENT sont les ajouts courants des hôtels (chambre,
      motif, pièce d'identité...). Ils existent TOUS en base dès cette
      migration, même ceux qu'aucun hôtel n'affiche : c'est ce qui permet
      d'adapter la fiche à un nouveau client par une simple ligne de
      configuration côté poste (section [FicheHotel] de claridoc.config), sans
      jamais rejouer une migration.

    Un champ vide ne signifie donc PAS « l'hôtel ne le demande pas » : il
    signifie « non renseigné ». C'est la configuration du poste, pas la base,
    qui dit ce qui est demandé.
    """
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='fiches_hotel')
    succursale = models.ForeignKey(
        Succursale, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='fiches_hotel'
    )

    # ── Numérotation ──────────────────────────────────────────────────────
    # Attribuée par le SERVEUR, jamais par le poste : deux établissements ne
    # doivent pas produire deux fiches n° 142. Séquentielle par client et par
    # année, remise à 1 au 1er janvier.
    annee = models.PositiveIntegerField(db_index=True)
    numero_fiche = models.PositiveIntegerField()

    # ── Socle standard (arrêté du 1er octobre 2015) ───────────────────────
    nom = models.CharField(max_length=150)
    prenom = models.CharField(max_length=150)
    date_naissance = models.DateField(null=True, blank=True)
    lieu_naissance = models.CharField(max_length=255, null=True, blank=True)
    nationalite = models.CharField(max_length=100, null=True, blank=True)
    domicile = models.TextField(null=True, blank=True)
    telephone = models.CharField(max_length=40, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    date_arrivee = models.DateTimeField(default=timezone.now)
    date_depart_prevue = models.DateField(null=True, blank=True)

    # ── Champs d'établissement (activés au cas par cas côté poste) ────────
    chambre = models.CharField(max_length=40, null=True, blank=True)
    sexe = models.CharField(max_length=10, null=True, blank=True)
    profession = models.CharField(max_length=150, null=True, blank=True)
    numero_identite = models.CharField(max_length=100, null=True, blank=True)
    date_expiration = models.DateField(null=True, blank=True)
    nombre_personnes = models.PositiveSmallIntegerField(default=1)
    motif_sejour = models.CharField(max_length=255, null=True, blank=True)
    provenance = models.CharField(max_length=255, null=True, blank=True)
    destination = models.CharField(max_length=255, null=True, blank=True)

    class TypeDocument(models.TextChoices):
        """Nature de la pièce présentée. Mêmes valeurs que Visiteur."""
        CNI = 'CNI', 'Carte nationale d\'identité'
        PASSEPORT = 'PASSEPORT', 'Passeport'
        AUTRE = 'AUTRE', 'Autre / non déterminé'

    # Comme pour Visiteur : le moteur OCR renvoie une valeur FINE
    # ('cni_2024_verso', 'passeport'...), ramenée à ces trois catégories par
    # le sérialiseur. Le backend reste la référence unique.
    type_document = models.CharField(
        max_length=20, choices=TypeDocument.choices,
        null=True, blank=True, db_index=True,
    )

    # ── Séjour et pièces produites ────────────────────────────────────────
    class StatutFiche(models.TextChoices):
        """Le client est-il encore dans l'établissement ?"""
        EN_COURS = 'EN_COURS', 'Séjour en cours'
        TERMINE = 'TERMINE', 'Séjour terminé'

    statut = models.CharField(
        max_length=20, choices=StatutFiche.choices, default=StatutFiche.EN_COURS
    )
    date_depart_reelle = models.DateTimeField(null=True, blank=True)

    # ── Séjour horaire (optionnel) ────────────────────────────────────────
    # Un hôtel peut louer une chambre à l'heure (chambre de repos, passage).
    # Si null → séjour en nuitées classique, rien ne change.
    # Si renseigné → heure_sortie_prevue est calculée par le backend au moment
    # de l'enregistrement : date_arrivee + duree_heures. On stocke le résultat
    # pour pouvoir répondre à la requête d'alertes sans calcul à la volée.
    duree_heures = models.PositiveSmallIntegerField(
        null=True, blank=True,
        help_text="Durée réservée en heures (séjour horaire). Null = séjour en nuitées."
    )
    heure_sortie_prevue = models.DateTimeField(
        null=True, blank=True,
        help_text="Calculée = date_arrivee + duree_heures. Nulle si séjour en nuitées."
    )

    fiche_pdf_chemin = models.TextField(null=True, blank=True)
    signee = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Options du modèle FicheHotel."""
        # Le couple (client, année, numéro) est l'identifiant métier de la
        # fiche : c'est lui qui garantit qu'un numéro n'est jamais réutilisé.
        unique_together = [('client', 'annee', 'numero_fiche')]
        ordering = ['-date_arrivee']

    def __str__(self):
        return f"Fiche {self.annee}-{self.numero_fiche:04d} · {self.nom} {self.prenom}"

    objects = models.Manager()


class FicheHotelAccompagnant(models.Model):
    """Enfant de moins de quinze ans accompagnant le voyageur.

    Table LIÉE et non colonne JSON : un registre doit pouvoir répondre à
    « qui se trouvait dans l'établissement le 12 mars », mineurs compris.
    Un bloc JSON rendrait cette question ininterrogeable.

    Les champs reprennent ceux du bloc « Accompanying children under 15 » du
    modèle standard.
    """
    fiche = models.ForeignKey(
        FicheHotel, on_delete=models.CASCADE, related_name='accompagnants'
    )
    nom = models.CharField(max_length=150)
    prenom = models.CharField(max_length=150, null=True, blank=True)
    date_naissance = models.DateField(null=True, blank=True)
    lieu_naissance = models.CharField(max_length=255, null=True, blank=True)
    nationalite = models.CharField(max_length=100, null=True, blank=True)

    class Meta:
        """Options du modèle FicheHotelAccompagnant."""
        ordering = ['id']

    def __str__(self):
        return f"{self.nom} {self.prenom or ''}".strip()

    objects = models.Manager()


class FicheHotelCoOccupant(models.Model):
    """Personne adulte (≥ 15 ans) co-occupant la chambre avec le voyageur principal.
    
    Possède sa propre pièce d'identité enregistrée au registre.
    """
    fiche = models.ForeignKey(
        FicheHotel, on_delete=models.CASCADE, related_name='co_occupants'
    )
    nom = models.CharField(max_length=150)
    prenom = models.CharField(max_length=150, null=True, blank=True)
    date_naissance = models.DateField(null=True, blank=True)
    lieu_naissance = models.CharField(max_length=255, null=True, blank=True)
    nationalite = models.CharField(max_length=100, null=True, blank=True)
    numero_identite = models.CharField(max_length=100, null=True, blank=True)
    type_document = models.CharField(max_length=20, null=True, blank=True)
    # Le co-occupant signe la fiche comme le voyageur principal. Seul le drapeau
    # remonte : l'encre est dans le PDF archivé sur le serveur de fichiers.
    signee = models.BooleanField(default=False)

    class Meta:
        """Options du modèle FicheHotelCoOccupant."""
        ordering = ['id']

    def __str__(self):
        return f"{self.nom} {self.prenom or ''}".strip()

    objects = models.Manager()


class ConfigFicheHotel(models.Model):
    """Configuration et personnalisation de la fiche hôtel par client.

    Permet d'adapter l'apparence (logo, en-tête, pied de page, couleur principale)
    et les champs affichés/obligatoires sur les fiches d'entrée.
    """
    client = models.OneToOneField(
        Client, on_delete=models.CASCADE, related_name='config_fiche_hotel'
    )

    # ── Charte graphique & PDF ───────────────────────────────────────────────
    logo = models.FileField(upload_to='logos_hotel/', null=True, blank=True)
    entete = models.TextField(null=True, blank=True)
    pied_de_page = models.TextField(null=True, blank=True)
    couleur_principale = models.CharField(max_length=7, default='#1a3c5e')

    # ── Configuration des champs d'établissement (JSON) ────────────────────
    # Contient la liste des champs configurables avec leur état :
    # [{"field": "chambre", "visible": true, "obligatoire": true,
    #   "ordre": 1, "libelle": "Numéro de chambre"}]
    champs = models.JSONField(default=list, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = models.Manager()

    def __str__(self):
        return f"Config Fiche Hôtel - {self.client.nom}"  # pylint: disable=no-member


class TicketCaisse(models.Model):
    """Ticket de caisse numérisé (onglet « Tickets de caisse » de l'appli).

    Deux familles sur la même table, distinguées par `type_ticket` :
      * VENTE — émis par la caisse du magasin (contrôle du chiffre du jour) ;
      * ACHAT — dépense rapportée par le personnel (contrôle des achats).

    Circuit (décision du 25/09/2026) : le USER scanne et enregistre, l'ADMIN et
    le BOSS contrôlent tous les tickets du client, seul le BOSS supprime.
    Comme les fichiers, visiteurs et fiches hôtel, le SUPERADMIN n'y a jamais
    accès : ce sont des données commerciales du client.

    TOUT ce qui a été lu est gardé : les champs reconnus, les lignes d'articles,
    le reste dans `autres_informations`, et le texte OCR complet dans
    `texte_ocr` pour pouvoir toujours revenir à la source.

    L'IMAGE du ticket, elle, ne remonte jamais au serveur (voir plus bas).
    """

    class TypeTicket(models.TextChoices):
        """Vente (caisse du magasin) ou achat (dépense)."""
        VENTE = 'VENTE', 'Vente'
        ACHAT = 'ACHAT', 'Achat'

    class StatutTicket(models.TextChoices):
        """Où en est le contrôle du ticket."""
        SAISI = 'SAISI', 'Saisi, à contrôler'
        CONTROLE = 'CONTROLE', 'Contrôlé'
        ANOMALIE = 'ANOMALIE', 'Anomalie signalée'

    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='tickets_caisse')
    succursale = models.ForeignKey(
        Succursale, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='tickets_caisse'
    )

    # Identifiant attribué par le POSTE à la création. La file de synchronisation
    # rejoue un envoi dont elle n'a pas reçu la réponse : sans cette clé, une
    # coupure réseau au mauvais moment enregistrerait le ticket deux fois — et
    # doublerait le chiffre du jour. Le serveur renvoie alors le ticket existant.
    uid_poste = models.UUIDField(null=True, blank=True, unique=True)

    type_ticket = models.CharField(
        max_length=10, choices=TypeTicket.choices, default=TypeTicket.VENTE, db_index=True
    )
    statut = models.CharField(
        max_length=20, choices=StatutTicket.choices, default=StatutTicket.SAISI, db_index=True
    )

    # ── En-tête du ticket ─────────────────────────────────────────────────
    enseigne = models.CharField(max_length=255, null=True, blank=True)
    adresse = models.TextField(null=True, blank=True)
    telephone = models.CharField(max_length=80, null=True, blank=True)
    niu = models.CharField(max_length=40, null=True, blank=True)
    rccm = models.CharField(max_length=80, null=True, blank=True)
    numero_ticket = models.CharField(max_length=80, null=True, blank=True, db_index=True)
    date_ticket = models.DateField(null=True, blank=True)
    heure_ticket = models.TimeField(null=True, blank=True)
    caisse = models.CharField(max_length=40, null=True, blank=True)
    caissier = models.CharField(max_length=150, null=True, blank=True)
    # « client » est déjà la société cliente de ClariDoc : le client inscrit
    # sur le ticket porte donc un autre nom.
    client_ticket = models.CharField(max_length=255, null=True, blank=True)

    # ── Totaux et règlement ───────────────────────────────────────────────
    sous_total = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)
    remise_totale = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)
    tva = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)
    total = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)
    mode_paiement = models.CharField(max_length=100, null=True, blank=True)
    montant_recu = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)
    monnaie_rendue = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)
    devise = models.CharField(max_length=10, default='FCFA')

    autres_informations = models.TextField(null=True, blank=True)
    texte_ocr = models.TextField(null=True, blank=True)
    # PAS d'image ni de chemin d'image ici, volontairement (décision du
    # 25/09/2026) : le patron voit sur le portail les CHIFFRES du ticket
    # (produits, totaux), jamais le ticket lui-même. L'image reste sur le
    # poste et le serveur de fichiers de l'agence.

    # ── Journée comptable ─────────────────────────────────────────────────
    # Jour auquel le ticket est rattaché pour la vérification de fin de
    # journée : la date imprimée si elle a été lue, sinon le jour de saisie.
    # Posé par le serveur (cf. TicketCaisseSerializer).
    journee = models.DateField(db_index=True)

    # ── Cohérence, recalculée par le SERVEUR à chaque écriture ────────────
    # Le poste affiche son propre contrôle, mais c'est celui-ci qui fait foi :
    # un poste d'une version antérieure ou une saisie manuelle ne peuvent pas
    # déclarer « cohérent » un ticket qui ne l'est pas.
    somme_articles = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)
    coherent = models.BooleanField(null=True, blank=True)

    # Arrivé (ou déplacé par une correction de date) dans une journée DÉJÀ
    # clôturée (décision du 15/10/2026) : le ticket est accepté, la clôture est
    # actualisée, et ce drapeau le signale « en retard ». Posé par le serveur,
    # jamais retiré : c'est un fait, pas un état.
    apres_cloture = models.BooleanField(default=False)

    # ── Traçabilité ───────────────────────────────────────────────────────
    saisi_par = models.ForeignKey(
        'User', on_delete=models.SET_NULL, null=True, blank=True, related_name='tickets_saisis'
    )
    controle_par = models.ForeignKey(
        'User', on_delete=models.SET_NULL, null=True, blank=True, related_name='tickets_controles'
    )
    date_controle = models.DateTimeField(null=True, blank=True)
    commentaire_controle = models.TextField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Options du modèle TicketCaisse."""
        ordering = ['-journee', '-created_at']
        indexes = [models.Index(fields=['client', 'journee'])]

    def __str__(self):
        return f"Ticket {self.get_type_ticket_display()} {self.numero_ticket or self.pk} · {self.total}"

    objects = models.Manager()


class TicketCaisseLigne(models.Model):
    """Ligne d'article d'un ticket de caisse.

    Table liée plutôt que JSON : le patron doit pouvoir demander « combien de
    sacs de ciment achetés ce mois-ci », ce qu'un bloc JSON rendrait
    ininterrogeable.
    """
    ticket = models.ForeignKey(TicketCaisse, on_delete=models.CASCADE, related_name='lignes')
    ordre = models.PositiveSmallIntegerField(default=0)
    code = models.CharField(max_length=40, null=True, blank=True)
    designation = models.CharField(max_length=255, null=True, blank=True)
    quantite = models.DecimalField(max_digits=12, decimal_places=3, null=True, blank=True)
    prix_unitaire = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)
    remise = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)
    montant = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)
    tva = models.CharField(max_length=20, null=True, blank=True)

    class Meta:
        """Options du modèle TicketCaisseLigne."""
        ordering = ['ordre', 'id']

    def __str__(self):
        return f"{self.designation or ''} {self.montant or ''}".strip()

    objects = models.Manager()


class ClotureCaisse(models.Model):
    """Clôture de la caisse pour une journée et une succursale.

    Ce que l'ADMIN ou le BOSS fait en fin de journée : il compte les espèces en
    caisse, les compare à ce que les tickets annoncent, et signe l'écart. C'est
    la pièce qui transforme une liste de tickets en un contrôle comptable.

    ────────────────────────────────────────────────────────────────────────
    UN TICKET EN RETARD EST ACCEPTÉ, ET LA CAISSE EST ACTUALISÉE
    ────────────────────────────────────────────────────────────────────────
    Règle du 15/10/2026 (elle remplace celle des totaux figés du 28/09).
    Un poste resté hors ligne peut remonter un ticket d'une journée déjà
    clôturée, ou une correction de date peut y déplacer un ticket. Le refuser
    le laisserait indéfiniment dans la file de reprise du poste (qui n'abandonne
    jamais) et ferait disparaître une recette. Il est donc accepté, la clôture
    est RECALCULÉE (totaux, nombre de tickets, écart avec les espèces comptées,
    qui, elles, ne bougent pas), et le ticket porte `apres_cloture` : il est
    signalé « en retard » au portail et sur le poste.

    Toute écriture du BOSS sur une journée close (correction, suppression)
    actualise de même la clôture. `desynchronise` reste calculé par sécurité.

    En revanche, MODIFIER ou SUPPRIMER un ticket déjà rangé dans une journée
    clôturée est refusé (sauf au BOSS) : là, il ne s'agit plus d'un retard
    mais d'une réécriture.
    """

    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='clotures_caisse')
    succursale = models.ForeignKey(
        Succursale, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='clotures_caisse'
    )
    journee = models.DateField(db_index=True)

    # ── Ce que les tickets annoncent (relevé à la clôture, actualisé par les
    #    tickets arrivés après — règle du 15/10/2026) ──────────────────────
    nb_tickets = models.PositiveIntegerField(default=0)
    total_ventes = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal('0'))
    total_achats = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal('0'))
    # ventes − achats : ce qui devrait se trouver en caisse.
    total_attendu = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal('0'))

    # ── Ce que l'agent a compté ───────────────────────────────────────────
    especes_comptees = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)
    # comptées − attendu. Négatif = il manque de l'argent en caisse.
    ecart = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)

    commentaire = models.TextField(null=True, blank=True)

    cloture_par = models.ForeignKey(
        'User', on_delete=models.SET_NULL, null=True, blank=True, related_name='clotures_caisse'
    )
    date_cloture = models.DateTimeField(auto_now_add=True)

    class Meta:
        """Options du modèle ClotureCaisse."""
        ordering = ['-journee', '-date_cloture']
        # Une seule clôture par journée et par point de vente. Reclôturer exige
        # de rouvrir d'abord — sinon deux clôtures contradictoires coexisteraient.
        constraints = [
            models.UniqueConstraint(
                fields=['client', 'succursale', 'journee'],
                name='cloture_unique_par_journee_et_succursale',
            )
        ]

    def __str__(self):
        return f"Clôture {self.journee} — attendu {self.total_attendu}, écart {self.ecart}"

    objects = models.Manager()
