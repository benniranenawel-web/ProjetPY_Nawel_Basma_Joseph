# TESTS AUTOMATIQUES DU PROJET


#   python -m pytest -v
# pytest lance toutes les fonctions qui commencent par "test_".
# "assert condition" : si la condition est fausse, le test echoue.

import inspect
from datetime import datetime, timedelta

from src.logs import lire_fichier, lire_plusieurs_fichiers
from src.transfo import parser_ligne, lire_connexion, lire_message
from src.filtres import construire_pipeline, ip_valide, router_log
from src.filtres import creer_compteurs, normaliser_log
from src.analyse import analyser_logs, comparer_blacklist
from src.analyse import charger_blacklist, detecter_force_brute
from src.regles import apply_security_rules, regle_trop_de_critiques
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


def test_yield_from_signale_le_fichier_manquant(tmp_path, capsys):
    (tmp_path / "a.log").write_text("a1\n", encoding="utf-8")
    (tmp_path / "c.log").write_text("c1\n", encoding="utf-8")
    chemins = [str(tmp_path / "a.log"), str(tmp_path / "b.log"),
               str(tmp_path / "c.log")]
    # le fichier du milieu manque : les autres sont quand meme lus
    assert list(lire_plusieurs_fichiers(chemins)) == ["a1", "c1"]
    # capsys recupere ce qui a ete affiche : l'erreur est signalee
    assert "n'existe pas" in capsys.readouterr().out


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


def test_ip_valide():
    # IP correctes, y compris les valeurs limites 0 et 255
    assert ip_valide("192.168.1.10") is True
    assert ip_valide("0.0.0.0") is True
    assert ip_valide("255.255.255.255") is True
    # IP fausses : trop grand, pas 4 nombres, lettres, chaine vide
    for ip in ["999.1.1.1", "10.0.0", "abc.1.2.3", "1.2.3.4.5", ""]:
        assert ip_valide(ip) is False
    # le pipeline rejette bien un log qui a une mauvaise IP
    ligne = LIGNE.replace("192.168.1.10", "999.1.1.1")
    assert list(construire_pipeline([ligne])) == []


def test_compteurs_du_pipeline():
    compteurs = creer_compteurs()
    lignes = ["", "", "ligne cassee", LIGNE.replace(":22/", ":99999/"),
              LIGNE, LIGNE]
    logs = construire_pipeline(lignes, compteurs)
    # pipeline paresseux : rien n'est compte tant qu'on ne le parcourt pas
    assert compteurs["lues"] == 0
    valides = list(logs)
    assert compteurs == {"lues": 6, "vides": 2, "fausses": 1, "invalides": 1}
    assert len(valides) == 2


def test_match_case():
    assert router_log("disk usage high") == "texte_brut"
    assert router_log(("1.1.1.1", 22, "TCP")) == "ssh"
    assert router_log(("1.1.1.1", 443, "TCP")) == "web"
    assert router_log(("1.1.1.1", 53, "UDP")) == "udp"
    assert router_log({"niveau": "CRITICAL", "message": "x"}) == "erreur"
    assert router_log({"event": "logout"}) == "logout"
    assert router_log(42) == "inconnu"


def test_normalisation_ligne_sale():
    ligne = ("2026-11-03T09:00:01 | warning | 10.0.0.5:80/TCP "
             "| user=  ALICE  |   Disk Usage HIGH  ")
    log = normaliser_log(parser_ligne(ligne))
    assert log["niveau"] == "WARNING"
    assert log["user"] == "alice"
    assert log["message"] == "disk usage high"
    assert "user=alice" in log["resume"]


def test_router_chaine():
    assert router_log("disk usage high") == "texte_brut"


def test_router_tuples():
    assert router_log(("1.1.1.1", 22, "TCP")) == "ssh"
    assert router_log(("1.1.1.1", 80, "TCP")) == "web"
    assert router_log(("1.1.1.1", 443, "TCP")) == "web"
    assert router_log(("1.1.1.1", 53, "UDP")) == "udp"


def test_router_dictionnaires():
    echec = {"niveau": "ERROR", "message": {"event": "login_failed"}}
    reussite = {"niveau": "INFO", "message": {"event": "login_success"}}
    # l'evenement est teste avant le niveau : echec reste un echec
    assert router_log(echec) == "echec_connexion"
    assert router_log(reussite) == "connexion_reussie"
    assert router_log({"niveau": "ERROR", "message": "x"}) == "erreur"
    assert router_log({"niveau": "INFO", "message": "x"}) == "normal"
    assert router_log({"event": "logout"}) == "logout"


def test_router_cas_par_defaut():
    assert router_log(42) == "inconnu"
    assert router_log({}) == "inconnu"
    # un tuple sur un port qu'on ne connait pas
    assert router_log(("1.1.1.1", 8080, "TCP")) == "inconnu"


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


def exemple_ensembles():
    """Resultat de comparer_blacklist sur un petit exemple connu."""
    return comparer_blacklist({"A", "C"}, {"C", "D"}, frozenset({"A", "B"}))


def test_operateur_union():
    # | : IP en erreur + blacklist
    assert exemple_ensembles()["a_surveiller"] == {"A", "B", "C", "D"}


def test_operateur_intersection():
    # & : IP blacklistees vues dans les logs
    assert exemple_ensembles()["blacklistees_actives"] == {"A"}


def test_operateur_difference():
    # - : le resultat depend du sens de la soustraction
    assert exemple_ensembles()["autorisees"] == {"C"}
    assert exemple_ensembles()["blacklistees_absentes"] == {"B"}


def test_operateur_difference_symetrique():
    # ^ : IP presentes d'un seul cote
    assert exemple_ensembles()["difference_symetrique"] == {"B", "C"}


def test_charger_blacklist(tmp_path):
    fichier = tmp_path / "blacklist.txt"
    fichier.write_text("# commentaire\n1.1.1.1\n\n  2.2.2.2  \n1.1.1.1\n",
                       encoding="utf-8")
    blacklist = charger_blacklist(str(fichier))
    # commentaire et ligne vide ignores, doublon retire, espaces enleves
    assert blacklist == {"1.1.1.1", "2.2.2.2"}
    assert type(blacklist) is frozenset
    # fichier absent : blacklist vide, sans planter
    assert charger_blacklist(str(tmp_path / "absent.txt")) == frozenset()


def test_force_brute_detectee():
    resultat = detecter_force_brute({"ip": creer_tentatives("SFFFFF")}, 5)
    assert resultat["ip"]["attaque"] is True


def test_reussite_remet_le_compteur_a_zero():
    resultat = detecter_force_brute({"ip": creer_tentatives("FFFFSFFFF")}, 5)
    assert resultat["ip"]["attaque"] is False
    assert resultat["ip"]["max_echecs"] == 4


def test_force_brute_branche_else_sans_attaque():
    resultat = detecter_force_brute({"ip": creer_tentatives("FFFFS")}, 5)
    # pas de break : c'est le else du while qui remplit le resultat
    assert resultat["ip"] == {"attaque": False, "max_echecs": 4, "heure": None}


def test_force_brute_branche_break_avec_attaque():
    tentatives = creer_tentatives("FFFFFFFF")
    resultat = detecter_force_brute({"ip": tentatives}, 5)
    assert resultat["ip"]["attaque"] is True
    # break au 5e echec : les 3 suivants ne sont pas lus
    assert resultat["ip"]["max_echecs"] == 5
    assert resultat["ip"]["heure"] == tentatives[4][0]


def attaque_detectee(secondes):
    """Dit si des echecs, aux instants donnes en secondes, forment une attaque."""
    debut = datetime(2026, 11, 3, 9, 0, 0)
    liste = [(debut + timedelta(seconds=s), "login_failed") for s in secondes]
    return detecter_force_brute({"ip": liste}, 5)["ip"]["attaque"]


def test_force_brute_fenetre_de_60_secondes():
    # 5 echecs en 30 s : attaque
    assert attaque_detectee([0, 5, 10, 20, 30]) is True
    # 5 echecs etales sur 10 minutes : pas d'attaque
    assert attaque_detectee([0, 150, 300, 450, 600]) is False
    # limite : 60 s pile est accepte, 61 s ne l'est plus
    assert attaque_detectee([0, 15, 30, 45, 60]) is True
    assert attaque_detectee([0, 15, 30, 45, 61]) is False
    # un 1er echec tres ancien n'empeche pas de voir les 5 suivants
    assert attaque_detectee([0, 1000, 1001, 1002, 1003, 1004]) is True


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


def regle_sans_parametre(**config):
    return ["alerte fixe"]


def test_moteur_sans_regle():
    assert apply_security_rules() == {}


def test_moteur_une_regle():
    assert apply_security_rules(regle_sans_parametre) == {
        "regle_sans_parametre": ["alerte fixe"]}


def test_moteur_plusieurs_regles():
    resultat = apply_security_rules(regle_sans_parametre, regle_test, seuil=1)
    assert resultat == {"regle_sans_parametre": ["alerte fixe"],
                        "regle_test": ["seuil = 1"]}


def test_moteur_transmet_les_kwargs():
    stats = {"par_niveau": {"CRITICAL": 10}}
    # meme regle, seul le parametre nomme change
    assert apply_security_rules(regle_trop_de_critiques, stats=stats,
                                seuil_critiques=5) == {
        "regle_trop_de_critiques": ["10 logs CRITICAL (seuil : 5)"]}
    assert apply_security_rules(regle_trop_de_critiques, stats=stats,
                                seuil_critiques=50) == {
        "regle_trop_de_critiques": []}


def test_audit_contient_une_variable_locale(tmp_path):
    variable_connue = 12345
    chemin = str(tmp_path / "audit.txt")
    exporter_audit(chemin, globals(), locals())
    with open(chemin, encoding="utf-8") as fichier:
        contenu = fichier.read()
    # on regarde seulement la partie du rapport qui vient de locals()
    partie_locale = contenu.split("VARIABLES LOCALES")[1]
    assert "variable_connue" in partie_locale
    assert str(variable_connue) in partie_locale


# ---------------- Le projet entier ----------------

def test_projet_complet_sur_les_donnees():
    fichiers = ["data/serveur1.log", "data/serveur2.log"]
    stats = analyser_logs(construire_pipeline(
        lire_plusieurs_fichiers(fichiers)))
    blacklist = charger_blacklist("data/blacklist.txt")
    ensembles = comparer_blacklist(stats["ips_actives"],
                                   stats["ips_erreur"], blacklist)
    force_brute = detecter_force_brute(stats["tentatives"], 5)
    attaques = [ip for ip in force_brute if force_brute[ip]["attaque"]]
    assert stats["nb_logs"] == 1878
    assert ensembles["blacklistees_actives"] == {"203.0.113.42",
                                                 "192.0.2.66"}
    assert sorted(attaques) == ["198.51.100.23",
                                "198.51.100.77", "203.0.113.42"]
