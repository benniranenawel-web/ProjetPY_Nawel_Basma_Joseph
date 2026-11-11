# MODULE 2 : nettoyer et classer les logs

from typing import Iterable, Iterator

# la fonction du Module 1 qui transforme une ligne en dict
from src.transfo import parser_ligne


def ip_valide(ip: str) -> bool:
    """True si l'IP contient 4 nombres entre 0 et 255 separes par des points."""
    morceaux = ip.split(".")
    # faut exactement 4 nombres
    if len(morceaux) != 4:
        return False
    for morceau in morceaux:
        # isascii() en plus : "²" passe isdigit() mais ferait planter int()
        if not (morceau.isascii() and morceau.isdigit()):
            return False
        # isdigit() refuse deja le signe "-" : il reste a verifier le maximum
        if int(morceau) > 255:
            return False
    return True


def est_valide(log: dict) -> bool:
    """True si le log a une bonne IP, un utilisateur, un bon port et protocole."""
    ip, port, protocole = log["connexion"]
    # adresse IP mal formee = log invalide
    if not ip_valide(ip):
        return False
    # utilisateur vide= log invalide
    if log["user"].strip() == "":
        return False
    # port entre 1 et 65535
    if port < 1 or port > 65535:
        return False
    # accepte que TCP et UDP
    if protocole not in ("TCP", "UDP"):
        return False
    # tout est bon
    return True


def normaliser_log(log: dict) -> dict:
    """Nettoie un log : niveau en majuscules, user en minuscules, etc."""
    # deballe le tuple de connexion
    ip, port, protocole = log["connexion"]
    # copie le dictionnaire pour pas modif l'original
    nouveau = dict(log)
    # "warning" devient "WARNING"
    nouveau["niveau"] = log["niveau"].upper()
    nouveau["user"] = log["user"].strip().lower()
    if isinstance(log["message"], str):
        nouveau["message"] = log["message"].strip().lower()
    heure = log["date"].strftime("%H:%M:%S")
    # :<8 = aligne a gauche sur 8 caracteres, :>15 = a droite sur 15
    nouveau["resume"] = (f"[{heure}] {nouveau['niveau']:<8} "
                         f"{ip:>15}:{port} {protocole} user={nouveau['user']}")
    # le log nettoye
    return nouveau


def creer_compteurs() -> dict:
    """Cree les compteurs de lignes du pipeline, tous a zero."""
    return {"lues": 0, "vides": 0, "fausses": 0, "invalides": 0}


def compter_ligne(ligne: str, compteurs: dict) -> str:
    """Compte une ligne lue (et si elle est vide) puis la renvoie intacte."""
    compteurs["lues"] += 1
    # meme test que filter(None, ...) : une ligne vide est consideree fausse
    if not ligne:
        compteurs["vides"] += 1
    return ligne


def garder_si_lisible(log: dict, compteurs: dict) -> bool:
    """True si parser_ligne a reussi, sinon compte une ligne fausse."""
    if log is None:
        compteurs["fausses"] += 1
        return False
    return True


def garder_si_valide(log: dict, compteurs: dict) -> bool:
    """True si le log est valide, sinon compte un log invalide."""
    if est_valide(log):
        return True
    compteurs["invalides"] += 1
    return False


def construire_pipeline(lignes: Iterable[str],
                        compteurs: dict = None) -> Iterator[dict]:
    """Enchaine toutes les etapes de nettoyage sur les lignes."""
    if compteurs is None:
        compteurs = creer_compteurs()
    lignes = map(lambda ligne: compter_ligne(ligne, compteurs), lignes)
    lignes = filter(None, lignes)
    logs = map(parser_ligne, lignes)
    logs = filter(lambda log: garder_si_lisible(log, compteurs), logs)
    logs = filter(lambda log: garder_si_valide(log, compteurs), logs)
    logs = map(normaliser_log, logs)
    return logs


def router_log(element: object) -> str:
    """Donne une categorie a un element selon sa forme (match-case)."""
    match element:
        case str():
            return "texte_brut"
        case (_, 22, "TCP"):
            return "ssh"
        case (_, 80 | 443, "TCP"):
            return "web"
        case (_, _, "UDP"):
            return "udp"
        case {"message": {"event": "login_failed"}}:
            return "echec_connexion"
        case {"message": {"event": "login_success"}}:
            return "connexion_reussie"
        case {"niveau": "ERROR" | "CRITICAL"}:
            return "erreur"
        case {"niveau": _}:
            return "normal"
        case {"event": nom}:
            return nom
        case _:
            return "inconnu"
