

import json
from datetime import datetime

NIVEAUX_VALIDES = ["INFO", "WARNING", "ERROR", "CRITICAL"]


def lire_connexion(texte: str) -> tuple[str, int, str]:

    adresse, protocole = texte.split("/")
    ip, port = adresse.split(":")
    return (ip, int(port), protocole)


def lire_message(texte: str) -> dict | str:
    """Renvoie un dictionnaire si le message est du JSON, sinon le texte."""
    try:
        contenu = json.loads(texte)
    except json.JSONDecodeError:
        return texte  # ce n'est pas du JSON : on garde le texte brut
    if isinstance(contenu, dict):
        return contenu
    return texte


def parser_ligne(ligne: str) -> dict | None:
    """Transforme une ligne en dictionnaire (None si la ligne est fausse)."""
    morceaux = ligne.split(" | ")

    # une ligne correcte a exactement 5 morceaux
    if len(morceaux) != 5:
        return None

    date_txt, niveau, connexion_txt, user_txt, message_txt = morceaux

    # on verifie que le niveau existe (la casse sera corrigee plus tard)
    if niveau.upper() not in NIVEAUX_VALIDES:
        return None

    # si la date ou le port ne sont pas valides, Python leve une ValueError
    try:
        date = datetime.fromisoformat(date_txt)
        connexion = lire_connexion(connexion_txt)
    except ValueError:
        return None

    return {"date": date,
            "niveau": niveau,
            "ip": connexion[0],
            "connexion": connexion,
            "user": user_txt.replace("user=", ""),
            "message": lire_message(message_txt), }
