"""Signature des co-occupants adultes de la fiche hôtel (16/09/2026).

Chaque adulte partageant la chambre signe la fiche comme le voyageur principal.
Seul le drapeau est stocké ici ; l'encre figure sur le PDF archivé.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0020_retrait_config_ftp_succursale'),
    ]

    operations = [
        migrations.AddField(
            model_name='fichehotelcooccupant',
            name='signee',
            field=models.BooleanField(default=False),
        ),
    ]
