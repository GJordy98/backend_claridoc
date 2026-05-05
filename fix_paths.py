"""
Script to fix FTP paths in the database to match the expected client code structure.
"""
import os
import django

# Configuration de l'environnement Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'claridoc_api.settings')
django.setup()

# pylint: disable=wrong-import-position
from accounts.models import Fichier

def corriger_chemins_ftp():
    """
    Iterates through all files and ensures their FTP path starts with the correct client code.
    """
    print("=== DÉBUT DE LA CORRECTION DES CHEMINS FTP ===")

    # On récupère tous les fichiers
    # pylint: disable=no-member
    fichiers = Fichier.objects.all()
    modifications = 0

    for fichier in fichiers:
        if not fichier.client or not fichier.chemin_ftp:
            continue

        code_client_attendu = fichier.client.code_client
        chemin_actuel = fichier.chemin_ftp

        # Si le fichier ne commence pas par le bon code client
        if not chemin_actuel.startswith(f"/{code_client_attendu}/"):
            # On extrait le nom et les sous-dossiers
            # Ex: /BNK-00001/stella/test1.pdf -> stella/test1.pdf
            parties = chemin_actuel.strip('/').split('/')

            # Si le premier dossier n'est pas le bon code client, on le remplace
            if len(parties) > 0 and parties[0] != code_client_attendu:
                ancien_chemin = chemin_actuel
                parties[0] = code_client_attendu
                nouveau_chemin = "/" + "/".join(parties)

                fichier.chemin_ftp = nouveau_chemin
                fichier.save()
                modifications += 1

                print(f"Correction : {ancien_chemin}  -->  {nouveau_chemin}")

    print(f"=== FIN : {modifications} fichier(s) mis à jour dans la base de données ===")

if __name__ == "__main__":
    corriger_chemins_ftp()
