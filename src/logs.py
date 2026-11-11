# MODULE 1 : lecture des logs avec des generateurs

# Un generateur renvoie les valeurs une par une avec "yield".
# Comme ca on ne met jamais tout le fichier en memoire (RAM).

import random
from datetime import datetime, timedelta
from typing import Iterator


def lire_fichier(chemin: str) -> Iterator[str]:
    """Lit un fichier ligne par ligne (generateur avec yield)."""
    try:
        with open(chemin, "r", encoding="utf-8") as fichier:
            for ligne in fichier:
                #strip() enleve  retour a la ligne "\n" et espaces
                yield ligne.strip()
    except FileNotFoundError:
        #si fichier existe pas on previent mais on plante pas
        print(f"Erreur : le fichier {chemin} n'existe pas")




def lire_plusieurs_fichiers(liste_chemins: list[str]) -> Iterator[str]:
    """Lit plusieurs fichiers a la suite (sous-generateur avec yield from)."""
    for chemin in liste_chemins:
        # yield from = renvoyer une par une toutes les lignes de lire_fichier
        yield from lire_fichier(chemin)
        
        
# Creation de faux logs pour tester le programme

NIVEAUX = ["INFO", "INFO", "INFO", "WARNING", "ERROR", "CRITICAL"]
UTILISATEURS = ["nawel", "basma", "joseph", "lola", "nora"]
IPS = ["192.168.1.10", "192.168.1.11", "10.0.0.5", "172.16.0.3"]
PORTS = [(22, "TCP"), (80, "TCP"), (443, "TCP"), (53, "UDP")]
# login_success est mis plusieurs fois pour que les echecs soient rares
EVENEMENTS = ["login_success", "login_success", "login_success",
              "login_success", "file_access", "logout", "login_failed"]

ECHEC = '{"event": "login_failed"}'
SUCCES = '{"event": "login_success"}'


def creer_ligne(heure: datetime, niveau: str, connexion: str,
                user: str, message: str) -> str:
    """Fabrique une ligne de log au format du projet."""
    return (f"{heure.isoformat()} | {niveau} | {connexion} "
            f"| user={user} | {message}")


def creer_ligne_sale(heure: datetime, niveau: str, connexion: str,
                     user: str, message: str) -> str:
    """Fabrique une ligne abimee, avec un defaut tire au hasard."""
    defaut = random.choice(["casse", "espaces", "ip", "tronquee"])
    if defaut == "casse":
        return creer_ligne(heure, niveau.lower(), connexion, user.upper(),
                           message)
    if defaut == "espaces":
        return creer_ligne(heure, niveau, connexion, f"  {user} ",
                           f"  {message}  ")
    if defaut == "ip":
        port_protocole = connexion.split(":")[1]
        return creer_ligne(heure, niveau, f"999.1.1.1:{port_protocole}",
                           user, message)
    ligne = creer_ligne(heure, niveau, connexion, user, message)
    return ligne[:len(ligne) // 2]


def ip_attaquante(i: int) -> str:
    """Renvoie l'IP qui attaque a la ligne i, ou "" s'il n'y a pas d'attaque."""
    if 300 <= i < 312 and i % 2 == 1:
        return "198.51.100.23"
    if 700 <= i < 712 and i % 2 == 1:
        return "198.51.100.77"
    return ""


def generer_logs(nb_lignes: int, graine: int = 42,
                 scenarios: bool = False) -> Iterator[str]:
    """Generateur qui fabrique des lignes de logs au hasard."""
    #meme graine = meme "hasard" = memes logs a chaque fois
    random.seed(graine)
    heure = datetime(2026, 11, 3, 9, 0, 0)

    for i in range(nb_lignes):
        heure = heure + timedelta(seconds=random.randint(1, 5))

        if i % 20 == 0:
            yield ""
            continue

        if scenarios and ip_attaquante(i) != "":
            yield creer_ligne(heure, "ERROR", f"{ip_attaquante(i)}:22/TCP",
                              "root", ECHEC)
            continue

        niveau = random.choice(NIVEAUX)
        ip = random.choice(IPS)
        port, protocole = random.choice(PORTS)
        user = random.choice(UTILISATEURS)

        if random.random() < 0.8:
            message = '{"event": "' + random.choice(EVENEMENTS) + '"}'
        else:
            message = "disk usage high"

        if i % 25 == 1:
            yield creer_ligne_sale(heure, niveau, f"{ip}:{port}/{protocole}",
                                   user, message)
            continue

        yield creer_ligne(heure, niveau, f"{ip}:{port}/{protocole}",
                          user, message)

    if not scenarios:
        return

    #Cas de test 

    # 1) attaque par force brute : 6 echecs de suite
    for i in range(6):
        heure = heure + timedelta(seconds=1)
        yield creer_ligne(heure, "ERROR", "203.0.113.42:22/TCP",
                          "admin", ECHEC)

    # 2) 4 echecs, 1 reussite, 3 echecs : ce n'est PAS une attaque
    for message in [ECHEC, ECHEC, ECHEC, ECHEC, SUCCES, ECHEC, ECHEC, ECHEC]:
        heure = heure + timedelta(seconds=2)
        yield creer_ligne(heure, "WARNING", "198.51.100.7:22/TCP",
                          "bob", message)

    # 3) une IP de la blacklist qui visite le site normalement
    for i in range(3):
        heure = heure + timedelta(seconds=3)
        yield creer_ligne(heure, "INFO", "192.0.2.66:443/TCP", "visiteur",
                          '{"event": "file_access"}')

    # 4) une ligne mal ecrite (minuscules, majuscules, espaces)
    yield creer_ligne(heure, "warning", "10.0.0.5:80/TCP", "ALICE",
                      "  Disk Usage HIGH  ")

    # 5) des lignes invalides qui doivent etre rejetees
    yield creer_ligne(heure, "INFO", "10.0.0.5:99999/TCP", "alice",
                      "port impossible")
    yield creer_ligne(heure, "INFO", "10.0.0.5:80/TCP", "",
                      "utilisateur vide")
    yield creer_ligne(heure, "DEBUG", "10.0.0.5:80/TCP", "alice",
                      "niveau inconnu")
    yield "ligne cassee"


def creer_fichier_test(chemin: str, nb_lignes: int, graine: int = 42,
                       scenarios: bool = False) -> None:
    """Ecrit les logs generes dans un fichier, ligne par ligne."""
    with open(chemin, "w", encoding="utf-8") as fichier:
        for ligne in generer_logs(nb_lignes, graine, scenarios):
            fichier.write(ligne + "\n")
