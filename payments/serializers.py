"""Serializers for the payments application."""
from rest_framework import serializers
from .models import SteevHubTransaction


class SteevHubTransactionSerializer(serializers.ModelSerializer):
    """Serializer for SteevHubTransaction model."""

    provider_label = serializers.CharField(
        source='get_provider_id_display',
        read_only=True
    )

    class Meta:
        model = SteevHubTransaction
        fields = [
            'id',
            'hub_reference',
            'pay_token',
            'provider_id',
            'provider_label',
            'telephone',
            'amount',
            'currency',
            'status',
            'created_at',
            'updated_at',
        ]
        read_only_fields = fields