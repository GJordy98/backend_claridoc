"""Script to inspect the latest licence and its associated PaymentRequest in the database."""
import os
import django

from accounts.models import Licence, PaymentRequest  # noqa: E402 (django.setup() called above)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'claridoc_api.settings')
django.setup()

# Récupérer la dernière licence créée
licence = Licence.objects.order_by('-id').first()  # pyright: ignore[reportAttributeAccessIssue]
if licence:
    client = licence.succursale.client  # pyright: ignore[reportOptionalMemberAccess]
    print(f"Dernière licence ID: {licence.id}")
    print(f"Succursale: {licence.succursale.nom}")  # pyright: ignore[reportOptionalMemberAccess]
    print(f"Client: {client.nom}")
    print(f"Email contact client: '{client.email_contact}'")

    # Vérifier la PaymentRequest associée
    pr = PaymentRequest.objects.filter(  # pyright: ignore[reportAttributeAccessIssue]
        succursale_cible=licence.succursale
    ).order_by('-id').first()
    if pr:
        print(f"PaymentRequest Statut: {pr.statut}")
else:
    print("Aucune licence trouvée en base.")
