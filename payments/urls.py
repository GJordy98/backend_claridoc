"""URL configuration for the payments application — Steeve Payment Hub."""
from django.urls import path
from .views import InitiatePaymentView, PaymentStatusView, SteevHubWebhookView

urlpatterns = [
    # Initie un paiement (JWT requis)
    path('initiate/', InitiatePaymentView.as_view(), name='payment-initiate'),

    # Vérifie le statut d'un paiement par référence (JWT requis)
    # Steeve recommande toujours de vérifier le statut
    path('status/<str:hub_reference>/', PaymentStatusView.as_view(), name='payment-status'),

    # Webhook appelé par le hub de Steeve (pas d'auth JWT)
    # À enregistrer chez Steeve : https://<votre-domaine>/api/payments/webhook/
    path('webhook/', SteevHubWebhookView.as_view(), name='payment-webhook'),
]
