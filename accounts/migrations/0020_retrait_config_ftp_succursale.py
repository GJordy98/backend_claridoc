"""Retire la configuration du serveur de fichiers de la plateforme (09/09/2026).

Les identifiants du serveur FileZilla de chaque client vivaient dans ces
colonnes, et partaient vers l'application dans la charge utile de licence
ACCOMPAGNES de la cle AES qui les dechiffre : le chiffrement en base n'etait pas
une protection, seulement un encodage. Le portail exposait meme le mot de passe
en clair aux administrateurs du client.

Cette configuration est desormais deposee chiffree sur le reseau de chaque
agence et lue par les postes avec une cle d'agence posee sur place par le
technicien. Elle n'a plus aucune raison d'exister ici.

IRREVERSIBLE PAR CONSTRUCTION : la migration inverse recree les colonnes mais ne
peut pas — et ne doit pas — restaurer les mots de passe. Les identifiants qui
etaient stockes ici sont a considerer comme compromis (ils ont aussi fuite via
le .env de production pousse sur le depot) et doivent etre changes dans
FileZilla, puis ressaisis sur site.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0019_fichehotelcooccupant'),
    ]

    operations = [
        migrations.RemoveField(model_name='succursale', name='ftp_host'),
        migrations.RemoveField(model_name='succursale', name='ftp_port'),
        migrations.RemoveField(model_name='succursale', name='ftp_user'),
        migrations.RemoveField(model_name='succursale', name='ftp_password_enc'),
        migrations.RemoveField(model_name='succursale', name='ftp_fingerprint'),
        migrations.RemoveField(model_name='succursale', name='ftp_base_path'),
    ]
