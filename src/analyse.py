# ============================================================
# MODULE 3 

# defaultdict : un dictionnaire qui donne une valeur par defaut
from collections import defaultdict
# Iterable sert au typage (une suite de logs qu'on parcourt)
from typing import Iterable

# on reutilise le match-case du Module 2 pour classer les logs
from src.filtres import router_log


def analyser_logs(logs: Iterable[dict]) -> dict:
    """Parcourt les logs une seule fois et calcule les statistiques."""
    # defaultdict(int) :  cle absente = 0 automatiquement,
    # donc on peut faire += 1 sans erreur KeyError
    par_niveau = defaultdict(int)
    par_user = defaultdict(int)
    par_categorie = defaultdict(int)
    par_connexion = defaultdict(int)
    # defaultdict(list) : une cle absente vaut une liste vide []
    tentatives = defaultdict(list)
    # un set garde chaque IP une seule fois, meme si elle revient 500 fois
    ips_actives = set()
    ips_erreur = set()
    # compteur du nombre de logs
    nb_logs = 0

    # on parcourt les logs un par un (viennent du pipeline)
    for log in logs:
        # un log de plus
        nb_logs += 1
        # +1 pour le niveau de ce log (INFO, ERROR...)
        par_niveau[log["niveau"]] += 1
        # +1 pour l'utilisateur de ce log
        par_user[log["user"]] += 1
        # +1 pour la categorie donnee par le match-case (dict)
        par_categorie[router_log(log)] += 1
        # +1 pour le type de connexion donne par le match-case (tuple)
        par_connexion[router_log(log["connexion"])] += 1
        # on ajoute l'IP a l'ensemble des IP vues
        ips_actives.add(log["ip"])
        # si le log est grave, on ajoute l'IP aux IP en erreur
        if log["niveau"] in ("ERROR", "CRITICAL"):
            ips_erreur.add(log["ip"])
        # si le message est un dict JSON, on regarde son evenement
        if isinstance(log["message"], dict):
            # .get() renvoie None si la cle "event" n'existe pas
            evenement = log["message"].get("event")
            # on garde seulement les tentatives de connexion
            if evenement in ("login_success", "login_failed"):
                # on range (date, evenement) dans la liste de cette IP
                tentatives[log["ip"]].append((log["date"], evenement))

    # on renvoie tous les resultats dans un dictionnaire
    return {
        "nb_logs": nb_logs,
        "par_niveau": par_niveau,
        "par_user": par_user,
        "par_categorie": par_categorie,
        "par_connexion": par_connexion,
        "tentatives": tentatives,
        "ips_actives": ips_actives,
        "ips_erreur": ips_erreur,}


def comparer_blacklist(ips_actives: set, ips_erreur: set,
                       blacklist: frozenset) -> dict:
    """Compare la blacklist (frozenset) avec les IP vues dans les logs."""
    return {
        # & intersection : IP blacklistees qui sont dans les logs
        "blacklistees_actives": blacklist & ips_actives,
        # - difference : IP des logs qui ne sont pas blacklistees
        "autorisees": ips_actives - blacklist,
        # - difference : IP blacklistees qu'on n'a jamais vues
        "blacklistees_absentes": blacklist - ips_actives,
        # ^ difference symetrique : IP d'un seul cote, pas des deux
        "difference_symetrique": blacklist ^ ips_actives,
        # | union : toutes les IP a surveiller (erreurs + blacklist)
        "a_surveiller": ips_erreur | blacklist,}


def detecter_force_brute(tentatives: dict, seuil: int = 5) -> dict:

    # dictionnaire des resultats : une entree par IP
    resultats = {}

    # boucle for : on prend chaque IP une par une
    for ip in tentatives:
        # on trie ses tentatives par date (ordre chronologique)
        liste = sorted(tentatives[ip])
        # nombre d'echecs d'affilee en ce moment
        echecs = 0
        # plus grand nombre d'echecs d'affilee vu pour cette IP
        max_echecs = 0
        # position dans la liste
        i = 0

        # boucle while : on avance dans les tentatives de cette IP
        while i < len(liste):
            # on deballe le tuple (date, evenement)
            date, evenement = liste[i]
            # on passe a la position suivante pour le prochain tour
            i += 1

            # connexion reussie : le compteur repart a zero
            if evenement == "login_success":
                echecs = 0
                # continue : on saute la suite et on passe au tour suivant
                continue

            # sinon c'est un echec : +1
            echecs += 1
            # on retient le record d'echecs d'affilee
            if echecs > max_echecs:
                max_echecs = echecs

            # seuil atteint : c'est une attaque par force brute
            if echecs >= seuil:
                resultats[ip] = {"attaque": True, "max_echecs": max_echecs,
                                 "heure": date}
                # break : on arrete le while, inutile de lire la suite
                break

        # le else d'une boucle s'execute SEULEMENT s'il n'y a pas eu de break
        else:
            # on a tout lu sans atteindre le seuil : l'IP est saine
            resultats[ip] = {"attaque": False, "max_echecs": max_echecs,
                             "heure": None}

    # on renvoie le resultat pour toutes les IP
    return resultats