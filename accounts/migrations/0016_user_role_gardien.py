# Ajout du rôle GARDIEN (registre des visiteurs), au même niveau hiérarchique
# que USER. Écrite à la main : l'opération est une simple AlterField de `choices`,
# sans changement de schéma réel (SQLite ne matérialise pas les choices Django).

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0015_visiteur_type_document'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.CharField(
                choices=[
                    ('SUPERADMIN', 'Super Admin ClariDoc'),
                    ('BOSS', "Chef d'entreprise"),
                    ('ADMIN', 'Administrateur Succursale'),
                    ('USER', 'Utilisateur (Scanner)'),
                    ('GARDIEN', 'Gardien (Registre visiteurs)'),
                ],
                default='USER',
                max_length=20,
            ),
        ),
    ]
