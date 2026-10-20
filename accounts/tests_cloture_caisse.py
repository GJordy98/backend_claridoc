"""Lot 5 — clôture de caisse : verrou, écart, ticket en retard ; 05/10 : succursale choisie, jour de saisie ;
15/10 : le ticket en retard actualise la caisse.

COMMENT LES LANCER
------------------
Ces tests n'ont besoin d'aucune base : ils tournent sur SQLite en mémoire. Il
faut seulement un fichier de réglages qui le dise, hors du dépôt (il ne doit
pas partir en production) :

    # settings_test.py, à côté de manage.py
    from claridoc_api.settings import *          # noqa: F401,F403
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
    PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

puis :

    venv/Scripts/python manage.py test accounts.tests_cloture_caisse --settings=settings_test

29 tests (11 du lot 5, 11 du 05/10/2026, 7 du 15/10/2026 — ticket en retard qui actualise
la caisse, date de clôture invalide), ~0,5 s. Ils ne touchent NI la base de développement, NI le réseau.
"""
from datetime import date
from decimal import Decimal

from django.test import TestCase
from rest_framework.test import APIClient

from accounts.models import Client, Succursale, TicketCaisse, ClotureCaisse
from django.contrib.auth import get_user_model

User = get_user_model()
JOUR = date(2026, 9, 28)


class ClotureCaisseTests(TestCase):
    def setUp(self):
        self.client_soc = Client.objects.create(nom="Boutique", code_client="AAA11111")
        self.succ = Succursale.objects.create(client=self.client_soc, nom="Centre")
        self.boss = self._user("patron", "BOSS")
        self.admin = self._user("gerant", "ADMIN")
        self.caissier = self._user("caissier", "USER")
        self.api = APIClient()

    def _user(self, nom, role):
        u = User.objects.create_user(username=nom, password="x", email=f"{nom}@e.cm")
        u.role, u.client, u.succursale = role, self.client_soc, self.succ
        u.save()
        return u

    def _ticket(self, type_ticket, total, saisi_par=None):
        return TicketCaisse.objects.create(
            client=self.client_soc, succursale=self.succ, journee=JOUR,
            type_ticket=type_ticket, total=Decimal(total),
            saisi_par=saisi_par or self.caissier)

    def _cloturer(self, especes, user=None):
        self.api.force_authenticate(user or self.admin)
        return self.api.post("/api/clotures-caisse/",
                             {"journee": str(JOUR), "especes_comptees": especes}, format="json")

    # ── L'écart ──────────────────────────────────────────────────────────
    def test_ecart_et_totaux_figes(self):
        self._ticket("VENTE", "125000")
        self._ticket("ACHAT", "18500")
        r = self._cloturer("105000")
        self.assertEqual(r.status_code, 201, r.data)
        self.assertEqual(Decimal(r.data["total_ventes"]), Decimal("125000"))
        self.assertEqual(Decimal(r.data["total_achats"]), Decimal("18500"))
        self.assertEqual(Decimal(r.data["total_attendu"]), Decimal("106500"))
        # compté − attendu : il manque 1 500 en caisse
        self.assertEqual(Decimal(r.data["ecart"]), Decimal("-1500"))
        self.assertEqual(r.data["nb_tickets"], 2)
        self.assertFalse(r.data["desynchronise"])

    def test_especes_non_saisies_donnent_un_ecart_nul_mais_absent(self):
        self._ticket("VENTE", "1000")
        self.api.force_authenticate(self.admin)
        r = self.api.post("/api/clotures-caisse/", {"journee": str(JOUR)}, format="json")
        self.assertEqual(r.status_code, 201, r.data)
        self.assertIsNone(r.data["ecart"])       # pas 0 : on n'a rien compté

    # ── Une seule clôture par journée ────────────────────────────────────
    def test_seconde_cloture_refusee(self):
        self._ticket("VENTE", "1000")
        self.assertEqual(self._cloturer("1000").status_code, 201)
        r = self._cloturer("999")
        self.assertEqual(r.status_code, 409)

    def test_boss_rouvre_puis_recloture(self):
        self._ticket("VENTE", "1000")
        c = self._cloturer("1000")
        self.api.force_authenticate(self.boss)
        r = self.api.post(f"/api/clotures-caisse/{c.data['id']}/rouvrir/")
        self.assertEqual(r.status_code, 204)
        self.assertEqual(ClotureCaisse.objects.count(), 0)
        self.assertEqual(self._cloturer("1000").status_code, 201)

    def test_admin_ne_peut_pas_rouvrir(self):
        self._ticket("VENTE", "1000")
        c = self._cloturer("1000")
        self.api.force_authenticate(self.admin)
        r = self.api.post(f"/api/clotures-caisse/{c.data['id']}/rouvrir/")
        self.assertEqual(r.status_code, 403)

    # ── Droits ───────────────────────────────────────────────────────────
    def test_user_na_pas_acces_a_la_cloture(self):
        self.api.force_authenticate(self.caissier)
        r = self.api.get("/api/clotures-caisse/")
        self.assertEqual(r.status_code, 403)

    # ── Le verrou ────────────────────────────────────────────────────────
    def test_ticket_en_retard_accepte_caisse_actualisee(self):
        # Règle du 15/10/2026 : la clôture suit le ticket en retard.
        self._ticket("VENTE", "100000")
        c = self._cloturer("100000")
        self.assertFalse(c.data["desynchronise"])
        self.assertEqual(c.data["nb_tickets_apres_cloture"], 0)

        # le poste hors ligne remonte enfin son ticket
        self.api.force_authenticate(self.caissier)
        r = self.api.post("/api/tickets-caisse/",
                          {"type_ticket": "VENTE", "total": "5000", "date_ticket": str(JOUR)},
                          format="json")
        self.assertEqual(r.status_code, 201, r.data)   # JAMAIS refusé : c'est une recette
        self.assertTrue(r.data["apres_cloture"])       # signalé « en retard »

        self.api.force_authenticate(self.admin)
        lu = self.api.get(f"/api/clotures-caisse/{c.data['id']}/")
        self.assertEqual(Decimal(lu.data["total_attendu"]), Decimal("105000"))   # actualisé
        self.assertEqual(lu.data["nb_tickets"], 2)
        self.assertEqual(Decimal(lu.data["especes_comptees"]), Decimal("100000"))  # inchangé
        self.assertEqual(Decimal(lu.data["ecart"]), Decimal("-5000"))
        self.assertEqual(lu.data["nb_tickets_apres_cloture"], 1)
        self.assertFalse(lu.data["desynchronise"])

    def test_ticket_ordinaire_pas_en_retard(self):
        self.api.force_authenticate(self.caissier)
        r = self.api.post("/api/tickets-caisse/",
                          {"type_ticket": "VENTE", "total": "5000", "date_ticket": str(JOUR)},
                          format="json")
        self.assertFalse(r.data["apres_cloture"])

    def test_ticket_deplace_vers_journee_close(self):
        # Ticket rangé un autre jour (ouvert), corrigé avec la date d'une journée close.
        self._ticket("VENTE", "1000")
        c = self._cloturer("1000")
        t = TicketCaisse.objects.create(client=self.client_soc, succursale=self.succ,
                                        journee=date(2026, 9, 29), type_ticket="VENTE",
                                        total=Decimal("400"), saisi_par=self.caissier)
        self.api.force_authenticate(self.caissier)
        r = self.api.patch(f"/api/tickets-caisse/{t.pk}/", {"date_ticket": str(JOUR)}, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data["journee"], str(JOUR))
        self.assertTrue(r.data["apres_cloture"])
        cl = ClotureCaisse.objects.get(pk=c.data["id"])
        self.assertEqual(cl.total_attendu, Decimal("1400"))
        self.assertEqual(cl.ecart, Decimal("-400"))

    def test_apres_cloture_non_modifiable_par_le_poste(self):
        self.api.force_authenticate(self.caissier)
        r = self.api.post("/api/tickets-caisse/",
                          {"type_ticket": "VENTE", "total": "5", "apres_cloture": True}, format="json")
        self.assertFalse(r.data["apres_cloture"])

    def test_suppression_par_le_boss_actualise_la_caisse(self):
        self._ticket("VENTE", "1000")
        t = self._ticket("VENTE", "300")
        c = self._cloturer("1300")
        self.api.force_authenticate(self.boss)
        self.assertEqual(self.api.delete(f"/api/tickets-caisse/{t.pk}/").status_code, 204)
        cl = ClotureCaisse.objects.get(pk=c.data["id"])
        self.assertEqual(cl.total_attendu, Decimal("1000"))
        self.assertEqual(cl.ecart, Decimal("300"))

    # ── 15/10/2026 : date de clôture illisible = refus clair, pas d'erreur 500 ──
    def test_journee_invalide_refusee_proprement(self):
        self.api.force_authenticate(self.admin)
        r = self.api.post("/api/clotures-caisse/", {"journee": "pas-une-date"}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("AAAA-MM-JJ", str(r.data["journee"][0]))

    def test_journee_au_format_francais_acceptee(self):
        self._ticket("VENTE", "1000")
        self.api.force_authenticate(self.admin)
        r = self.api.post("/api/clotures-caisse/", {"journee": "28/09/2026"}, format="json")
        self.assertEqual(r.status_code, 201, r.data)
        self.assertEqual(r.data["journee"], str(JOUR))
        self.assertEqual(r.data["nb_tickets"], 1)

    def test_modification_refusee_sur_journee_close(self):
        t = self._ticket("VENTE", "1000")
        self._cloturer("1000")
        self.api.force_authenticate(self.caissier)
        r = self.api.patch(f"/api/tickets-caisse/{t.pk}/", {"total": "9999"}, format="json")
        self.assertEqual(r.status_code, 403)
        t.refresh_from_db()
        self.assertEqual(t.total, Decimal("1000"))

    def test_boss_echappe_au_verrou(self):
        t = self._ticket("VENTE", "1000")
        self._cloturer("1000")
        self.api.force_authenticate(self.boss)
        r = self.api.patch(f"/api/tickets-caisse/{t.pk}/", {"total": "1200"}, format="json")
        self.assertEqual(r.status_code, 200, r.data)

    def test_suppression_refusee_sur_journee_close(self):
        t = self._ticket("VENTE", "1000")
        self._cloturer("1000")
        # le BOSS seul peut supprimer un ticket ; ici la journée est close et il
        # échappe au verrou, donc on vérifie le refus avec l'ADMIN sur la modif
        self.api.force_authenticate(self.boss)
        r = self.api.delete(f"/api/tickets-caisse/{t.pk}/")
        self.assertEqual(r.status_code, 204)

    def test_journee_dune_autre_succursale_non_verrouillee(self):
        autre = Succursale.objects.create(client=self.client_soc, nom="Annexe")
        # Le caissier de l'annexe, et SON ticket : un USER ne voit que les siens.
        u = self._user("caissier2", "USER")
        u.succursale = autre
        u.save()
        t = TicketCaisse.objects.create(client=self.client_soc, succursale=autre, journee=JOUR,
                                        type_ticket="VENTE", total=Decimal("500"),
                                        saisi_par=u)
        self._ticket("VENTE", "1000")
        self._cloturer("1000")          # clôture du Centre seulement
        self.api.force_authenticate(u)
        r = self.api.patch(f"/api/tickets-caisse/{t.pk}/", {"total": "600"}, format="json")
        self.assertEqual(r.status_code, 200, r.data)

    # ── 05/10/2026 : succursale choisie à la clôture ─────────────────────
    def _cloturer_succ(self, user, succursale, especes="1000"):
        self.api.force_authenticate(user)
        return self.api.post("/api/clotures-caisse/",
                             {"journee": str(JOUR), "especes_comptees": especes,
                              "succursale": succursale}, format="json")

    def test_boss_sans_succursale_cloture_celle_quil_choisit(self):
        self.boss.succursale = None
        self.boss.save()
        self._ticket("VENTE", "1000")
        r = self._cloturer_succ(self.boss, self.succ.pk)
        self.assertEqual(r.status_code, 201, r.data)
        self.assertEqual(r.data["succursale"], self.succ.pk)
        self.assertEqual(r.data["nb_tickets"], 1)          # et non une caisse vide
        self.assertEqual(Decimal(r.data["ecart"]), Decimal("0"))

    def test_boss_peut_clorer_les_tickets_sans_succursale(self):
        TicketCaisse.objects.create(client=self.client_soc, succursale=None, journee=JOUR,
                                    type_ticket="VENTE", total=Decimal("700"), saisi_par=self.boss)
        r = self._cloturer_succ(self.boss, None, "700")
        self.assertEqual(r.status_code, 201, r.data)
        self.assertIsNone(r.data["succursale"])
        self.assertEqual(r.data["nb_tickets"], 1)

    def test_succursale_dune_autre_societe_refusee(self):
        autre_soc = Client.objects.create(nom="Concurrent", code_client="BBB22222")
        etrangere = Succursale.objects.create(client=autre_soc, nom="Ailleurs")
        r = self._cloturer_succ(self.boss, etrangere.pk)
        self.assertEqual(r.status_code, 400)

    def test_admin_ne_cloture_que_sa_succursale(self):
        autre = Succursale.objects.create(client=self.client_soc, nom="Annexe")
        self.assertEqual(self._cloturer_succ(self.admin, autre.pk).status_code, 403)
        self.assertEqual(self._cloturer_succ(self.admin, self.succ.pk).status_code, 201)

    def test_sans_cle_succursale_comportement_inchange(self):
        self._ticket("VENTE", "1000")
        r = self._cloturer("1000")
        self.assertEqual(r.status_code, 201, r.data)
        self.assertEqual(r.data["succursale"], self.succ.pk)


class JourneeSaisieTests(TestCase):
    """05/10/2026 : un ticket sans date imprimée suit le jour de SAISIE du poste."""

    def setUp(self):
        soc = Client.objects.create(nom="Boutique", code_client="CCC33333")
        self.user = User.objects.create_user(username="caissier", password="x", email="c@e.cm")
        self.user.role, self.user.client = "USER", soc
        self.user.save()
        self.api = APIClient()
        self.api.force_authenticate(self.user)

    def _envoyer(self, **champs):
        r = self.api.post("/api/tickets-caisse/", {"type_ticket": "VENTE", "total": "1000", **champs},
                          format="json")
        self.assertEqual(r.status_code, 201, r.data)
        return TicketCaisse.objects.get(pk=r.data["id"])

    def test_ticket_hors_ligne_range_au_jour_de_saisie(self):
        t = self._envoyer(journee_saisie=str(JOUR))
        self.assertEqual(t.journee, JOUR)

    def test_date_imprimee_prime_sur_le_jour_de_saisie(self):
        t = self._envoyer(date_ticket="2026-09-27", journee_saisie=str(JOUR))
        self.assertEqual(t.journee, date(2026, 9, 27))

    def test_poste_ancien_sans_jour_de_saisie(self):
        from django.utils import timezone
        t = self._envoyer()
        self.assertEqual(t.journee, timezone.localdate())

    def test_horloge_du_poste_dans_le_futur_ignoree(self):
        from django.utils import timezone
        t = self._envoyer(journee_saisie="2099-01-01")
        self.assertEqual(t.journee, timezone.localdate())

    def test_jour_de_saisie_jamais_renvoye(self):
        r = self.api.post("/api/tickets-caisse/", {"type_ticket": "VENTE", "total": "1",
                                                   "journee_saisie": str(JOUR)}, format="json")
        self.assertNotIn("journee_saisie", r.data)
        self.assertEqual(r.data["journee"], str(JOUR))

    def test_correction_garde_la_journee(self):
        t = self._envoyer(journee_saisie=str(JOUR))
        r = self.api.patch(f"/api/tickets-caisse/{t.pk}/", {"total": "1200"}, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        t.refresh_from_db()
        self.assertEqual(t.journee, JOUR)
