"""Models for the payments application, tracking transactions via Steeve's payment hub."""
from django.db import models
from accounts.models import PaymentRequest


PROVIDER_CHOICES = [
    (1, 'Orange Money'),
    (2, 'MTN Mobile Money'),
    (3, 'Carte (Visa/Mastercard)'),
]


class SteevHubTransaction(models.Model):
    """
    Tracks payment transactions processed via Steeve's centralized payment hub.

    Lifecycle: PENDING → SUCCESS | FAILED
    The hub_reference (UUID from Steeve) is the key to check or receive status updates.
    """
    payment_request = models.OneToOneField(
        PaymentRequest,
        on_delete=models.CASCADE,
        related_name='steeve_transaction'
    )

    # Steeve hub identifiers
    hub_reference = models.CharField(
        max_length=100, unique=True,
        help_text="UUID retourné par le hub (payment.reference)"
    )
    pay_token = models.CharField(
        max_length=200, null=True, blank=True,
        help_text="Token de paiement mobile (pay_token)"
    )

    # Payment details
    provider_id = models.IntegerField(
        choices=PROVIDER_CHOICES,
        help_text="1=Orange Money, 2=MTN MoMo, 3=Carte"
    )
    telephone = models.CharField(
        max_length=30, null=True, blank=True,
        help_text="Numéro du payeur (format international ex: 237XXXXXXXXX)"
    )
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=10, default='XAF')

    # Status mirrors Steeve hub values: PENDING, SUCCESS, FAILED
    status = models.CharField(max_length=20, default='PENDING')

    # Full raw response stored for audit/debug
    raw_response = models.JSONField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = models.Manager()

    class Meta:
        verbose_name = "Transaction Hub Steeve"
        verbose_name_plural = "Transactions Hub Steeve"
        ordering = ['-created_at']

    def __str__(self):
        provider = dict(PROVIDER_CHOICES).get(self.provider_id, '?')
        return f"[{self.status}] {provider} — {self.amount} XAF (ref: {self.hub_reference[:12]}...)"
