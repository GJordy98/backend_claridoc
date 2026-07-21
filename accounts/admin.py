"""Configuration de l'interface d'administration Django pour l'application accounts."""

from typing import Any
from django.contrib import admin
from .models import Client, Succursale, Licence, Machine, User, Fichier, Log, PaymentRequest


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    """Administration des clients (entreprises)."""

    list_display: Any = ('nom', 'code_client', 'statut', 'is_active', 'created_at')
    list_filter = ('statut', 'is_active')
    search_fields = ('nom', 'code_client', 'email_contact')


@admin.register(Succursale)
class SuccursaleAdmin(admin.ModelAdmin):
    """Administration des succursales rattachées aux clients."""

    list_display: Any = ('nom', 'client', 'ville', 'storage_mode')
    list_filter = ('storage_mode',)
    search_fields = ('nom', 'client__nom')


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    """Administration des utilisateurs de l'application."""

    list_display: Any = ('username', 'email', 'role', 'client', 'is_active')
    list_filter = ('role', 'is_active')
    search_fields = ('username', 'email')


@admin.register(Licence)
class LicenceAdmin(admin.ModelAdmin):
    """Administration des licences associées aux succursales."""

    list_display: Any = ('succursale', 'max_machines', 'date_fin', 'code_activation')
    search_fields = ('code_activation', 'succursale__nom')


@admin.register(Machine)
class MachineAdmin(admin.ModelAdmin):
    """Administration des machines enregistrées sous licence."""

    list_display: Any = ('hwid', 'nom_machine', 'licence', 'is_active', 'last_seen')
    list_filter = ('is_active',)
    search_fields = ('hwid', 'nom_machine')


@admin.register(PaymentRequest)
class PaymentRequestAdmin(admin.ModelAdmin):
    """Administration des demandes de paiement et de renouvellement de licence."""

    list_display: Any = (
        'client', 'forfait_postes', 'forfait_duree',
        'moyen_paiement', 'statut', 'created_at'
    )
    list_filter = ('statut', 'moyen_paiement')
    search_fields = ('client__nom',)


@admin.register(Fichier)
class FichierAdmin(admin.ModelAdmin):
    """Administration des fichiers uploadés par les clients."""

    list_display: Any = ('nom_fichier', 'client', 'statut_upload', 'created_at')
    list_filter = ('statut_upload',)


@admin.register(Log)
class LogAdmin(admin.ModelAdmin):
    """Administration des logs d'activité des utilisateurs."""

    list_display: Any = ('user', 'client', 'action', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('action', 'user__username')
