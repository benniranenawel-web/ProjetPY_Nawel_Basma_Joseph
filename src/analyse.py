# MODULE 3

# defaultdict= un dico qui donne une valeur
from collections import defaultdict
# Iterable=une suite de logs qu'on parcourt
from typing import Iterable

# reutilise le match-case du Module 2 pour classer les logs
from src.filtres import router_log
# reutilise le generateur du Module 1 pour lire la blacklist
from src.logs import lire_fichier


def analyser_logs(logs: Iterable[dict]) -> dict:
    """Parcourt les logs une seule fois et calcule les statistiques."""
    # defaultdict(int)= cle absente = 0 automatiquement,
    par_niveau = defaultdict(int)
    par_user = defaultdict(int)
    par_categorie = defaultdict(int)
    par_connexion = defaultdict(int)
    # defaultdict(list)=une cle absente vaut une liste vide []
    tentatives = defaultdict(list)
    ips_actives = set()
    ips_erreur = set()
    nb_logs = 0

    for log in logs:
        nb_logs += 1
        par_niveau[log["niveau"]] += 1
        par_user[log["user"]] += 1
        par_categorie[router_log(log)] += 1
        par_connexion[router_log(log["connexion"])] += 1
        ips_actives.add(log["ip"])
        if log["niveau"] in ("ERROR", "CRITICAL"):
            ips_erreur.add(log["ip"])
        if isinstance(log["message"], dict):
            evenement = log["message"].get("event")
            if evenement in ("login_success", "login_failed"):
                tentatives[log["ip"]].append((log["date"], evenement))

    return {
        "nb_logs": nb_logs,
        "par_niveau": par_niveau,
        "par_user": par_user,
        "par_categorie": par_categorie,
        "par_connexion": par_connexion,
        "tentatives": tentatives,
        "ips_actives": ips_actives,
        "ips_erreur": ips_erreur, }


def charger_blacklist(chemin: str) -> frozenset[str]:
    """Lit la blacklist (une IP par ligne) et la renvoie en frozenset."""
    ips = filter(lambda ligne: ligne and not ligne.startswith("#"),
                 lire_fichier(chemin))
    return frozenset(ips)


def comparer_blacklist(ips_actives: set, ips_erreur: set,
                       blacklist: frozenset) -> dict:
    """Compare la blacklist (frozenset) avec les IP vues dans les logs."""
    return {
        "blacklistees_actives": blacklist & ips_actives,
        "autorisees": ips_actives - blacklist,
        "blacklistees_absentes": blacklist - ips_actives,
        "difference_symetrique": blacklist ^ ips_actives,
        "a_surveiller": ips_erreur | blacklist, }


def detecter_force_brute(tentatives: dict, seuil: int = 5,
                         fenetre: int = 60) -> dict:

    resultats = {}

    for ip in tentatives:
        liste = sorted(tentatives[ip])
        echecs = 0
        max_echecs = 0
        dates_echecs = []
        i = 0

        while i < len(liste):
            date, evenement = liste[i]
            i += 1

            if evenement == "login_success":
                echecs = 0
                dates_echecs = []
                continue

            echecs += 1
            dates_echecs.append(date)
            # le record d'echecs d'affilee
            if echecs > max_echecs:
                max_echecs = echecs

            # seuil atteint= mesure le temps pris par les derniers echecs
            if echecs >= seuil:
                ecart = date - dates_echecs[-seuil]
                if ecart.total_seconds() <= fenetre:
                    resultats[ip] = {"attaque": True, "max_echecs": max_echecs,
                                     "heure": date}
                    break

        else:
            resultats[ip] = {"attaque": False, "max_echecs": max_echecs,
                             "heure": None}
    return resultats
