# ============================================================
# MODULE 4 : moteur de regles de securite
# (*args, **kwargs, fonctions passees en argument)
# ============================================================
# Une "regle" est une fonction qui :
#   - recoit les donnees dont elle a besoin par **config
#   - renvoie une liste d'alertes (des phrases)
# Le moteur apply_security_rules lance toutes les regles qu'on lui
# donne, sans avoir besoin de savoir a l'avance lesquelles.


def regle_blacklist(**config) -> list[str]:
    """Alerte pour chaque IP blacklistee vue dans les logs."""
    # liste vide qu'on va remplir avec les alertes
    alertes = []
    # on recupere le resultat de comparer_blacklist (Module 3)
    ensembles = config["ensembles"]
    # sorted() pour avoir toujours les IP dans le meme ordre
    for ip in sorted(ensembles["blacklistees_actives"]):
        # une alerte par IP interdite trouvee
        alertes.append("IP blacklistee active : " + ip)
    # on renvoie la liste (vide s'il n'y a rien)
    return alertes


def regle_force_brute(**config) -> list[str]:
    """Alerte pour chaque IP qui a fait une attaque par force brute."""
    # liste vide qu'on va remplir avec les alertes
    alertes = []
    # resultat de detecter_force_brute (Module 3) : {ip: {...}}
    resultats = config["force_brute"]
    # on parcourt les IP dans l'ordre
    for ip in sorted(resultats):
        # on ne garde que les IP marquees comme attaque
        if resultats[ip]["attaque"]:
            # on transforme l'heure (datetime) en texte "09:50:00"
            heure = resultats[ip]["heure"].strftime("%H:%M:%S")
            # on ajoute l'alerte
            alertes.append("Force brute depuis " + ip + " a " + heure)
    # on renvoie la liste des alertes
    return alertes


def regle_trop_de_critiques(**config) -> list[str]:
    """Alerte si le nombre de logs CRITICAL depasse un seuil."""
    # .get() et pas [] : lire une cle absente d'un defaultdict la creerait
    nb_critiques = config["stats"]["par_niveau"].get("CRITICAL", 0)
    # seuil facultatif : 100 par defaut s'il n'est pas donne
    seuil = config.get("seuil_critiques", 100)
    # trop de CRITICAL -> une alerte
    if nb_critiques > seuil:
        # str() car on ne peut pas coller un nombre a du texte avec +
        return [str(nb_critiques) + " logs CRITICAL (seuil : "
                + str(seuil) + ")"]
    # sinon aucune alerte
    return []


def apply_security_rules(*regles, **config) -> dict[str, list[str]]:
    """Applique toutes les regles recues et regroupe leurs alertes.

    *regles  : toutes les fonctions de regle, rangees dans un tuple
    **config : tous les parametres nommes, ranges dans un dictionnaire
    Renvoie un dictionnaire {nom de la regle: liste d'alertes}.
    """
    # dictionnaire des resultats, rempli regle par regle
    resultats = {}
    # regles est un tuple : on le parcourt comme une liste
    for regle in regles:
        # securite : on verifie que c'est bien une fonction
        if not callable(regle):
            print("Ignore (ce n'est pas une fonction) :",(regle))
            # on passe a la regle suivante
            continue
        # une regle peut avoir besoin d'une donnee qu'on n'a pas donnee
        try:
            # **config "deplie" le dictionnaire en parametres nommes :
            # regle(**{"stats": s}) revient a regle(stats=s)
            alertes = regle(**config)
        except KeyError as erreur:
            # on previent sans faire planter tout le programme
            print("Regle", regle.__name__, "ignoree : il manque", erreur)
            continue
        # __name__ donne le nom de la fonction, ex : "regle_blacklist"
        resultats[regle.__name__] = alertes
    # on renvoie toutes les alertes, rangees par regle
    return resultats