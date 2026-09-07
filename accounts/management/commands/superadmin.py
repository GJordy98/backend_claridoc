"""
Gestion du compte SUPERADMIN du portail ClariDoc.

Pourquoi une commande dédiée plutôt que `createsuperuser` : le modèle User de
ClariDoc porte un champ `role` propre, dont la valeur par défaut est `USER`.
`createsuperuser` positionne `is_staff` et `is_superuser` — utiles pour
l'administration Django — mais laisse `role` à `USER`. Or c'est `role` que lisent
le portail web (`proxy.ts`, page de connexion) et toutes les vues de l'API. Un
compte créé par `createsuperuser` se connecte donc sans jamais atteindre /admin.

Exemples
--------
    python manage.py superadmin
        Liste les comptes SUPERADMIN existants, sans rien modifier.

    python manage.py superadmin --email admin@claridoc.com --password "MonMotDePasse"
        Crée le compte s'il n'existe pas, ou le répare s'il existe : rôle
        SUPERADMIN, compte actif, mot de passe redéfini.
"""

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model

User = get_user_model()


class Command(BaseCommand):
    help = "Liste, crée ou répare un compte SUPERADMIN du portail ClariDoc."

    def add_arguments(self, parser):
        parser.add_argument('--email', help="Adresse email du compte.")
        parser.add_argument('--password', help="Mot de passe à définir.")
        parser.add_argument(
            '--username',
            help="Identifiant. Par défaut, la partie de l'email avant le @.",
        )

    def handle(self, *args, **options):
        email = (options.get('email') or '').strip()
        password = options.get('password') or ''
        username = (options.get('username') or '').strip()

        # Sans argument : on se contente de rendre compte de l'existant. Un tel
        # inventaire est le premier geste utile quand la connexion échoue — il
        # distingue « aucun superadmin » de « superadmin inactif » et de « mot de
        # passe oublié », trois pannes qui se ressemblent depuis la page de login.
        if not email:
            comptes = User.objects.filter(role='SUPERADMIN').order_by('username')
            if not comptes.exists():
                self.stdout.write(self.style.WARNING(
                    "Aucun compte SUPERADMIN dans cette base.\n"
                    "Créez-en un :\n"
                    "  python manage.py superadmin --email vous@exemple.com --password \"…\""
                ))
                return

            self.stdout.write(f"{comptes.count()} compte(s) SUPERADMIN :")
            for u in comptes:
                etat = "actif" if u.is_active else "INACTIF"
                self.stdout.write(f"  · {u.username}  <{u.email or 'sans email'}>  [{etat}]")
            self.stdout.write(
                "\nMot de passe oublié ? Relancez avec --email et --password "
                "pour le redéfinir."
            )
            return

        if not password:
            raise CommandError("--password est requis dès lors que --email est fourni.")

        # Recherche par email d'abord : c'est ce que saisit l'utilisateur sur le
        # portail, et le sérialiseur de connexion le traduit en username.
        utilisateur = User.objects.filter(email__iexact=email).first()
        if utilisateur is None and username:
            utilisateur = User.objects.filter(username__iexact=username).first()

        cree = utilisateur is None
        if cree:
            utilisateur = User(
                username=username or email.split('@')[0],
                email=email,
            )

        utilisateur.email = email
        utilisateur.role = 'SUPERADMIN'
        utilisateur.is_active = True
        # is_staff / is_superuser donnent en plus l'accès à l'admin Django ; sans
        # eux, un SUPERADMIN du portail resterait bloqué devant /django-admin.
        utilisateur.is_staff = True
        utilisateur.is_superuser = True
        utilisateur.set_password(password)
        utilisateur.save()

        verbe = "créé" if cree else "mis à jour"
        self.stdout.write(self.style.SUCCESS(
            f"Compte SUPERADMIN {verbe} : {utilisateur.username} <{utilisateur.email}>"
        ))
        self.stdout.write(
            "Connexion sur http://localhost:3000/login avec cette adresse email "
            "et ce mot de passe ; le portail redirigera vers /admin."
        )
