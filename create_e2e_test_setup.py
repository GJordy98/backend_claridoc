"""
Script pour créer automatiquement la pile de comptes et la licence de test E2E.
Exécution : python create_e2e_test_setup.py (depuis le dossier Web_Backend)
"""
import os
from datetime import date, timedelta


def setup_e2e():
    """Configure l'environnement de test E2E avec les comptes et la licence nécessaires."""
    # Django setup must happen before model imports
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'claridoc_api.settings')

    # pylint: disable=import-outside-toplevel
    import django
    django.setup()

    from django.contrib.auth import get_user_model
    from accounts.models import Client, Licence, Succursale
    from payments.services import _generate_activation_code
    # pylint: enable=import-outside-toplevel

    User = get_user_model()  # pylint: disable=invalid-name
    print("=" * 60)
    print("🚀 INITIALISATION DE L'ENVIRONNEMENT DE TEST E2E")
    print("=" * 60)

    # 1. Création / Récupération du SuperAdmin
    superadmin, created = User.objects.get_or_create(
        username='superadmin',
        defaults={
            'email': 'superadmin@claridoc.com',
            'role': User.RoleChoices.SUPERADMIN,
            'is_staff': True,
            'is_superuser': True,
            'first_name': 'Super',
            'last_name': 'Admin'
        }
    )
    if created:
        superadmin.set_password('Admin123!')
        superadmin.save()
        print("✅ SuperAdmin créé : superadmin / Admin123!")
    else:
        print("ℹ️ SuperAdmin existant : superadmin")

    # 2. Création du Client (Entreprise)
    client, created = Client.objects.get_or_create(
        code_client='CLI-E2E-TEST',
        defaults={
            'nom': 'Société Test E2E',
            'email_contact': 'boss.e2e@example.com',
            'telephone': '+237690000000',
            'statut': Client.StatutClient.ACTIF
        }
    )
    if created:
        print(f"✅ Client créé : {client.nom} ({client.code_client})")
    else:
        client.statut = Client.StatutClient.ACTIF
        client.save()
        print(f"ℹ️ Client existant : {client.nom}")

    # 3. Création de la Succursale
    succursale, created = Succursale.objects.get_or_create(  # type: ignore[attr-defined]  # pylint: disable=no-member
        client=client,
        nom='Siège Principal Test',
        defaults={
            'ville': 'Douala',
            'adresse': 'Akwa Boulevard'
        }
    )
    if created:
        print(f"✅ Succursale créée : {succursale.nom}")
    else:
        print(f"ℹ️ Succursale existante : {succursale.nom}")

    # 4. Compte BOSS (Chef d'entreprise)
    boss, created = User.objects.get_or_create(
        username='boss_e2e',
        defaults={
            'email': 'boss.e2e@example.com',
            'role': User.RoleChoices.BOSS,
            'client': client,
            'first_name': 'Jean',
            'last_name': 'Boss'
        }
    )
    if created:
        boss.set_password('Boss123!')
        boss.save()
        print("✅ Compte BOSS créé : boss_e2e / Boss123!")
    else:
        print("ℹ️ Compte BOSS existant : boss_e2e")

    # 5. Compte ADMIN Succursale
    admin_succ, created = User.objects.get_or_create(
        username='admin_e2e',
        defaults={
            'email': 'admin.e2e@example.com',
            'role': User.RoleChoices.ADMIN,
            'client': client,
            'succursale': succursale,
            'first_name': 'Marc',
            'last_name': 'Admin'
        }
    )
    if created:
        admin_succ.set_password('Admin123!')
        admin_succ.save()
        print("✅ Compte ADMIN Succursale créé : admin_e2e / Admin123!")
    else:
        print("ℹ️ Compte ADMIN existant : admin_e2e")

    # 6. Compte USER (Scanner C# Desktop)
    user_scanner, created = User.objects.get_or_create(
        username='user_e2e',
        defaults={
            'email': 'user.e2e@example.com',
            'role': User.RoleChoices.USER,
            'client': client,
            'succursale': succursale,
            'first_name': 'Paul',
            'last_name': 'Scanner'
        }
    )
    if created:
        user_scanner.set_password('User123!')
        user_scanner.save()
        print("✅ Compte USER Scanner créé : user_e2e / User123!")
    else:
        print("ℹ️ Compte USER existant : user_e2e")

    # 7. Génération de la Licence
    code_activation = _generate_activation_code()
    licence, created = Licence.objects.get_or_create(  # type: ignore[attr-defined]  # pylint: disable=no-member
        succursale=succursale,
        defaults={
            'date_fin': date.today() + timedelta(days=365),
            'max_machines': 5,
            'code_activation': code_activation,
        }
    )
    if not created:
        licence.date_fin = date.today() + timedelta(days=365)
        licence.max_machines = 5
        licence.code_activation = code_activation
        licence.save()
        print("🔄 Licence renouvelée avec le nouveau code d'activation")
    else:
        print(f"✅ Licence créée pour {succursale.nom}")

    print("\n" + "=" * 60)
    print("📋 RÉCAPITULATIF DES IDENTIFIANTS DE TEST E2E")
    print("=" * 60)
    print(f"🔑 CODE ACTIVATION LICENCE : {licence.code_activation}")
    print(f"📅 Fin de validité        : {licence.date_fin} (5 postes max)")
    print(f"🏢 Client                  : {client.nom} ({client.code_client})")
    print(f"📍 Succursale              : {succursale.nom}")
    print("-" * 60)
    print("👤 Compte SUPERADMIN       : superadmin / Admin123!")
    print("👑 Compte BOSS (Web Admin) : boss_e2e / Boss123!")
    print("🛡️ Compte ADMIN Agence     : admin_e2e / Admin123!")
    print("📷 Compte USER (App C#)    : user_e2e / User123!")
    print("=" * 60)


if __name__ == '__main__':
    setup_e2e()
