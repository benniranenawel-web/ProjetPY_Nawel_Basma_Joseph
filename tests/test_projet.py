# ============================================================
# TESTS AUTOMATIQUES DU PROJET
# ============================================================
# Pour les lancer (dans PowerShell, depuis le dossier du projet) :
#   python -m pytest -v
# pytest lance toutes les fonctions qui commencent par "test_".
# "assert condition" : si la condition est fausse, le test echoue.

import inspect
from datetime import datetime

from src.logs import lire_fichier, lire_plusieurs_fichiers
from src.transfo import parser_ligne, lire_connexion, lire_message
from src.filtres import construire_pipeline, router_log
from src.analyse import analyser_logs, comparer_blacklist
from src.analyse import detecter_force_brute
from src.regles import apply_security_rules
from src.audit import exporter_audit

# une ligne de log correcte, reutilisee dans plusieurs tests
LIGNE = ('2026-11-03T09:00:01 | ERROR | 192.168.1.10:22/TCP '
         '| user=alice | {"event": "login_failed"}')


# ---------------- Module 1 : lecture ----------------

def test_lire_fichier_est_un_generateur(tmp_path):
    # tmp_path : dossier temporaire fourni par pytest
    fichier = tmp_path / "a.log"
    fichier.write_text("ligne 1\nligne 2\n", encoding="utf-8")
    # c'est bien une fonction generateur (avec yield)
    assert inspect.isgeneratorfunction(lire_fichier)
    # elle renvoie les lignes sans le "\n"
    assert list(lire_fichier(str(fichier))) == ["ligne 1", "ligne 2"]


def test_yield_from_enchaine_les_fichiers(tmp_path):
    (tmp_path / "a.log").write_text("a1\na2\n", encoding="utf-8")
    (tmp_path / "b.log").write_text("b1\n", encoding="utf-8")
    chemins = [str(tmp_path / "a.log"), str(tmp_path / "absent.log"),
               str(tmp_path / "b.log")]
    # le fichier absent est ignore, les autres sont lus dans l'ordre
    assert list(lire_plusieurs_fichiers(chemins)) == ["a1", "a2", "b1"]


# ---------------- Module 1 : transformation ----------------

def test_parser_ligne_correcte():
    log = parser_ligne(LIGNE)
    assert log["date"] == datetime(2026, 11, 3, 9, 0, 1)
    assert log["niveau"] == "ERROR"
    assert log["user"] == "alice"
    assert log["message"] == {"event": "login_failed"}


def test_connexion_est_un_tuple():
    assert lire_connexion("10.0.0.5:22/TCP") == ("10.0.0.5", 22, "TCP")


def test_message_json_ou_texte():
    assert lire_message('{"event": "logout"}') == {"event": "logout"}
    assert lire_message("disk usage high") == "disk usage high"


def test_lignes_fausses_renvoient_none():
    assert parser_ligne("ligne cassee") is None
    assert parser_ligne(LIGNE.replace("ERROR", "DEBUG")) is None
    assert parser_ligne(LIGNE.replace(":22/", ":abc/")) is None


# ---------------- Module 2 : filtres ----------------

def test_pipeline_filtre_et_nettoie():
    lignes = [
        "",                                           # ligne vide
        "ligne cassee",                               # mauvais format
        LIGNE.replace(":22/", ":99999/"),             # port impossible
        LIGNE.replace("user=alice", "user="),         # user vide
        LIGNE.replace("ERROR", "error").replace("alice", "ALICE"),
    ]
    logs = list(construire_pipeline(lignes))
    # il ne reste que la derniere ligne, nettoyee
    assert len(logs) == 1
    assert logs[0]["niveau"] == "ERROR"
    assert logs[0]["user"] == "alice"


def test_match_case():
    assert router_log("disk usage high") == "texte_brut"
    assert router_log(("1.1.1.1", 22, "TCP")) == "ssh"
    assert router_log(("1.1.1.1", 443, "TCP")) == "web"
    assert router_log(("1.1.1.1", 53, "UDP")) == "udp"
    assert router_log({"niveau": "CRITICAL", "message": "x"}) == "erreur"
    assert router_log({"event": "logout"}) == "logout"
    assert router_log(42) == "inconnu"


# ---------------- Module 3 : analyse ----------------

def creer_tentatives(texte):
    """'FFS' -> echec, echec, succes (une seconde d'ecart entre chaque)."""
    liste = []
    for i in range(len(texte)):
        if texte[i] == "F":
            evenement = "login_failed"
        else:
            evenement = "login_success"
        liste.append((datetime(2026, 11, 3, 9, 0, i), evenement))
    return liste


def test_defaultdict_et_sets():
    stats = analyser_logs(construire_pipeline([LIGNE, LIGNE]))
    assert stats["nb_logs"] == 2
    assert stats["par_user"]["alice"] == 2
    assert stats["ips_actives"] == {"192.168.1.10"}
    assert stats["ips_erreur"] == {"192.168.1.10"}


def test_operations_ensembles():
    resultat = comparer_blacklist({"A", "C"}, {"C"}, frozenset({"A", "B"}))
    assert resultat["blacklistees_actives"] == {"A"}
    assert resultat["autorisees"] == {"C"}
    assert resultat["blacklistees_absentes"] == {"B"}
    assert resultat["difference_symetrique"] == {"B", "C"}
    assert resultat["a_surveiller"] == {"A", "B", "C"}


def test_force_brute_detectee():
    resultat = detecter_force_brute({"ip": creer_tentatives("SFFFFF")}, 5)
    assert resultat["ip"]["attaque"] is True


def test_reussite_remet_le_compteur_a_zero():
    resultat = detecter_force_brute({"ip": creer_tentatives("FFFFSFFFF")}, 5)
    assert resultat["ip"]["attaque"] is False
    assert resultat["ip"]["max_echecs"] == 4


# ---------------- Module 4 : regles et audit ----------------

def regle_test(**config):
    return ["seuil = " + str(config["seuil"])]


def test_moteur_de_regles():
    # une regle + un parametre
    assert apply_security_rules(regle_test, seuil=3) == {
        "regle_test": ["seuil = 3"]}
    # quelque chose qui n'est pas une fonction est ignore
    assert apply_security_rules("pas une fonction", seuil=3) == {}
    # un parametre manquant ne fait pas planter
    assert apply_security_rules(regle_test) == {}


def test_audit_globals_locals(tmp_path):
    ma_variable = [1, 2, 3]
    chemin = str(tmp_path / "audit.txt")
    exporter_audit(chemin, globals(), locals())
    contenu = open(chemin, encoding="utf-8").read()
    # regle_test vient de globals(), ma_variable de locals()
    assert "regle_test" in contenu
    assert "ma_variable" in contenu


# ---------------- Le projet entier ----------------

def test_projet_complet_sur_les_donnees():
    fichiers = ["data/serveur1.log", "data/serveur2.log"]
    stats = analyser_logs(construire_pipeline(
        lire_plusieurs_fichiers(fichiers)))
    blacklist = frozenset({"203.0.113.42", "192.0.2.66", "192.0.2.99"})
    ensembles = comparer_blacklist(stats["ips_actives"],
                                   stats["ips_erreur"], blacklist)
    force_brute = detecter_force_brute(stats["tentatives"], 5)
    attaques = [ip for ip in force_brute if force_brute[ip]["attaque"]]
    assert stats["nb_logs"] == 1918
    assert ensembles["blacklistees_actives"] == {"203.0.113.42",
                                                 "192.0.2.66"}
    assert attaques == ["203.0.113.42"]
    