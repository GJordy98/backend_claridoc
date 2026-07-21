"""Script to inspect a specific user, their client, and NotchPay transactions."""
import os
import django

from accounts.models import User  # noqa: E402
from payments.models import NotchPayTransaction  # noqa: E402

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'claridoc_api.settings')
django.setup()

# 1. Vérifier l'utilisateur rosesurway
user = User.objects.filter(email='rosesurway@gmail.com').first()  # type: ignore[attr-defined]
if user:
    print(f"Utilisateur: {user.email}")
    print(f"Client associé: {user.client.nom if user.client else 'AUCUN'}")
    print(f"Email contact client: '{user.client.email_contact}'")

    if user.client:
        # 2. Chercher la dernière transaction pour ce client
        tx = NotchPayTransaction.objects.filter(  # type: ignore[attr-defined]
            payment_request__client=user.client
        ).order_by('-id').first()
        if tx:
            print(
                f"Dernière transaction trouvée: {tx.transaction_reference}"
                f" (Statut: {tx.status})"
            )
            # Voir tous les utilisateurs du même client
            peers = User.objects.filter(client=user.client)  # type: ignore[attr-defined]
            print(f"Autres utilisateurs du même client ({user.client.nom}):")
            for p in peers:
                print(f" - {p.email} (Actif: {p.is_active})")
        else:
            print(f"Aucune transaction NotchPay trouvée pour le client {user.client.nom}")
else:
    print("Utilisateur rosesurway@gmail.com introuvable.")
