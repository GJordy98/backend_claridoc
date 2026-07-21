"""
Models for the accounts application, defining Clients, Succursales, Users, and Licences.
"""
import datetime
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

    # Configuration FTP indépendante par succursale
    ftp_host = models.CharField(max_length=255, default='127.0.0.1')
    ftp_port = models.IntegerField(default=21)
    ftp_user = models.CharField(max_length=150, default='claridoc_ftp')
    ftp_password_enc = models.TextField(null=True, blank=True)
    ftp_fingerprint = models.CharField(max_length=255, null=True, blank=True)
    ftp_base_path = models.CharField(max_length=255, default='/ClariDoc_Cloud/')
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

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.nom} {self.prenom} - {self.statut}"

    objects = models.Manager()
