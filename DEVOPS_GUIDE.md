# 🚀 Guide de Déploiement Production Backend — ClariDoc Pro

Ce document détaille les instructions d'installation et de mise en ligne du backend Django (`Web_Backend`) pour l'équipe DevOps / Administrateur système.

---

## 📦 1. Contenu de l'archive (`claridoc_backend_deploy.zip`)
- **Code source Django** (`accounts`, `payments`, `claridoc_api`)
- **Dossiers de migrations** (incluant la migration `0019_fichehotelcooccupant` pour les co-occupants adultes)
- **Fichier de configuration production** (`.env` pré-configuré pour la prod, `DEBUG=False`)
- **Dépendances requises** (`requirements.txt` avec `gunicorn`, `psycopg2-binary`, `dj-database-url`, `whitenoise`, `Pillow`...)

---

## ⚙️ 2. Prérequis serveur Linux (Ubuntu / Debian / CentOS / Hostinger)
- **Python** : 3.10 ou supérieur (`python3`, `python3-venv`, `python3-pip`)
- **PostgreSQL** : 13 ou supérieur
- **Nginx** (Reverse Proxy & SSL)
- **Supervisor** ou **Systemd** (Process Manager)

---

## 🛠️ 3. Étapes d'installation pas-à-pas

### Étape A — Extraction du projet
```bash
# Se placer dans le répertoire d'application
mkdir -p /var/www/claridoc_backend
cd /var/www/claridoc_backend

# Extraire le zip
unzip /path/to/claridoc_backend_deploy.zip -d .
```

### Étape B — Environnement virtuel & Dépendances
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Étape C — Configuration des variables d'environnement (`.env`)
Vérifier et ajuster le fichier `.env` si nécessaire :
```env
DEBUG=False
SECRET_KEY=votre_cle_secrete_ultra_securisee
ALLOWED_HOSTS=api.clairidocpro.com,217.160.47.83

# Base de données PostgreSQL
DB_NAME=claridoc_pro_V2
DB_USER=postgres
DB_PASSWORD=votre_mot_de_passe
DB_HOST=127.0.0.1
DB_PORT=5432
# Ou via DATABASE_URL:
# DATABASE_URL=postgres://postgres:motdepasse@127.0.0.1:5432/claridoc_pro_V2

# HTTPS & CORS
USE_HTTPS=1
CORS_ALLOW_ALL=0
CORS_ALLOWED_ORIGINS=https://www.clairidocpro.com,https://clairidocpro.com
CSRF_TRUSTED_ORIGINS=https://www.clairidocpro.com,https://api.clairidocpro.com
```

### Étape D — Migrations de Base de Données & Fichiers Statiques
```bash
# Exécuter les migrations (crée/met à jour les tables dont fiches_hotel_cooccupants)
python manage.py migrate

# Collecter les fichiers statiques (servis par WhiteNoise / Nginx)
python manage.py collectstatic --noinput

# Créer les dossiers media et attribuer les droits
mkdir -p media/logos_hotel
chmod -R 775 media staticfiles
```

---

## 🔌 4. Configuration Systemd (Service Gunicorn)

Créer `/etc/systemd/system/claridoc.service` :
```ini
[Unit]
Description=Gunicorn daemon for ClariDoc Pro Backend
After=network.target postgresql.service

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/claridoc_backend
ExecStart=/var/www/claridoc_backend/venv/bin/gunicorn \
          --access-logfile /var/log/gunicorn/access.log \
          --error-logfile /var/log/gunicorn/error.log \
          --workers 4 \
          --bind 127.0.0.1:8000 \
          claridoc_api.wsgi:application

Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Démarrer le service :
```bash
sudo systemctl daemon-reload
sudo systemctl enable claridoc
sudo systemctl start claridoc
sudo systemctl status claridoc
```

---

## 🌐 5. Configuration Nginx (Reverse Proxy & Certificat SSL)

Créer `/etc/nginx/sites-available/claridoc_backend` :
```nginx
server {
    listen 80;
    server_name api.clairidocpro.com;

    client_max_body_size 20M;

    location /static/ {
        alias /var/www/claridoc_backend/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }

    location /media/ {
        alias /var/www/claridoc_backend/media/;
        expires 7d;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Activer le site & SSL Certbot :
```bash
sudo ln -s /etc/nginx/sites-available/claridoc_backend /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Certificat SSL gratuit Certbot Let's Encrypt
sudo certbot --nginx -d api.clairidocpro.com
```

---

## ✅ 6. Vérification Post-Déploiement
- **Vérification API Health Check** : `curl https://api.clairidocpro.com/api/v1/fiches-hotel/`
- **Logs d'erreur Gunicorn** : `tail -f /var/log/gunicorn/error.log`
- **Logs Nginx** : `tail -f /var/log/nginx/error.log`

---
*Guide généré automatiquement pour le déploiement de ClariDoc Pro.*
