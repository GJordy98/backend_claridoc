"""Admin configuration for the payments application — Steeve Payment Hub."""
from django.contrib import admin
from .models import SteevHubTransaction, PROVIDER_CHOICES

_PROVIDER_MAP = dict(PROVIDER_CHOICES)


@admin.register(SteevHubTransaction)
class SteevHubTransactionAdmin(admin.ModelAdmin):
    """Admin interface for managing Steeve Hub payment transactions."""
    list_display = (
        'hub_reference', 'payment_request', 'get_provider_name',
        'telephone', 'amount', 'status', 'created_at'
    )
    list_filter = ('status', 'provider_id', 'created_at')
    search_fields = (
        'hub_reference', 'pay_token',
        'payment_request__client__nom', 'telephone'
    )
    readonly_fields = (
        'hub_reference', 'pay_token', 'provider_id', 'telephone',
        'amount', 'currency', 'raw_response', 'created_at', 'updated_at'
    )

    @admin.display(description='Provider')
    def get_provider_name(self, obj):
        """Retourne le nom lisible du provider."""
        return _PROVIDER_MAP.get(obj.provider_id, f'Provider {obj.provider_id}')
