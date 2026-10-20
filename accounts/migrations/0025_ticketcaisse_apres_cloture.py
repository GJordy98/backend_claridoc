# Écrite à la main le 15/10/2026 (équivalent de makemigrations).

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0024_cloture_caisse'),
    ]

    operations = [
        migrations.AddField(
            model_name='ticketcaisse',
            name='apres_cloture',
            field=models.BooleanField(default=False),
        ),
    ]
