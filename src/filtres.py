# MODULE 2 : nettoyer et classer les logs

from typing import Iterable, Iterator

# on reutilise la fonction du Module 1 qui transforme une ligne en dict
from src.transfo import parser_ligne

def ip_valide(ip: str) -> bool:
    """True si l'IP contient 4 nombres entre 0 et 255 separes par des points."""
    morceaux = ip.split(".")
    # il faut exactement 4 nombres
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
    # on "deballe" le tuple (ip, port, protocole) en 3 variables
    ip, port, protocole = log["connexion"]
    # adresse IP mal formee -> log invalide
    if not ip_valide(ip):
        return False
    # utilisateur vide -> log invalide
    if log["user"].strip() == "":
        return False
    # un port existe seulement entre 1 et 65535
    if port < 1 or port > 65535:
        return False
    # on accepte seulement TCP et UDP
    if protocole not in ("TCP", "UDP"):
        return False
    # si on arrive ici, tout est bon
    return True


def normaliser_log(log: dict) -> dict:
    """Nettoie un log : niveau en majuscules, user en minuscules, etc."""
    # on deballe le tuple de connexion
    ip, port, protocole = log["connexion"]
    # on copie le dictionnaire pour ne pas modifier l'original
    nouveau = dict(log)
    # "warning" devient "WARNING"
    nouveau["niveau"] = log["niveau"].upper()
    # " ALICE " devient "alice"
    nouveau["user"] = log["user"].strip().lower()
    # si le message est du texte (et pas un dict JSON)...
    if isinstance(log["message"], str):
        # ...on enleve les espaces et on met en minuscules
        nouveau["message"] = log["message"].strip().lower()
    # on transforme la date en texte, par exemple "09:00:07"
    heure = log["date"].strftime("%H:%M:%S")
    # resume lisible avec une f-string
    # :<8 = aligne a gauche sur 8 caracteres, :>15 = a droite sur 15
    nouveau["resume"] = (f"[{heure}] {nouveau['niveau']:<8} "
                         f"{ip:>15}:{port} {protocole} user={nouveau['user']}")
    # on renvoie le log nettoye
    return nouveau


def construire_pipeline(lignes: Iterable[str]) -> Iterator[dict]:
    """Enchaine toutes les etapes de nettoyage sur les lignes."""
    # filter(None, ...) garde ce qui est "vrai" : "" est faux, donc
    # les lignes vides disparaissent
    lignes = filter(None, lignes)
    # map() applique parser_ligne a chaque ligne : on obtient dict ou None
    logs = map(parser_ligne, lignes)
    # lambda = petite fonction sans nom : on enleve les None (lignes fausses)
    logs = filter(lambda log: log is not None, logs)
    # on passe la fonction est_valide elle-meme (sans parentheses) a filter
    logs = filter(est_valide, logs)
    # map() applique normaliser_log a chaque log restant
    logs = map(normaliser_log, logs)
    # rien n'est encore calcule : tout se fait quand on parcourt logs
    return logs


def router_log(element: object) -> str:
    """Donne une categorie a un element selon sa forme (match-case)."""
    # on compare la forme de element a chaque "case", dans l'ordre
    match element:
        # une chaine de texte
        case str():
            return "texte_brut"
        # un tuple dont le 2e element vaut 22 et le 3e "TCP"
        # ("_" veut dire : n'importe quelle valeur)
        case (_, 22, "TCP"):
            return "ssh"
        # un tuple avec le port 80 OU 443 en TCP
        case (_, 80 | 443, "TCP"):
            return "web"
        # un tuple avec n'importe quel port en UDP
        case (_, _, "UDP"):
            return "udp"
        # un dict dont le message est un echec de connexion
        case {"message": {"event": "login_failed"}}:
            return "echec_connexion"
        # un dict dont le message est une connexion reussie
        case {"message": {"event": "login_success"}}:
            return "connexion_reussie"
        # un dict avec un niveau grave
        case {"niveau": "ERROR" | "CRITICAL"}:
            return "erreur"
        # n'importe quel autre log (il a une cle "niveau")
        case {"niveau": _}:
            return "normal"
        # un message JSON comme {"event": "logout"} : on renvoie l'event
        case {"event": nom}:
            return nom
        # tout le reste
        case _:
            return "inconnu"
