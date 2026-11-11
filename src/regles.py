# MODULE 4 : moteur de regles de securite


def regle_blacklist(**config) -> list[str]:
    """Alerte pour chaque IP blacklistee vue dans les logs."""
    alertes = []
    #recup le resultat de comparer_blacklist (Module 3)
    ensembles = config["ensembles"]
    #sorted() pour avoir les IP dans le mm ordre
    for ip in sorted(ensembles["blacklistees_actives"]):
        alertes.append("IP blacklistee active : " + ip)
    return alertes


def regle_force_brute(**config) -> list[str]:
    """Alerte pour chaque IP qui a fait une attaque par force brute."""
    alertes = []
    #resultat de detecter_force_brute (Module 3) : {ip: {...}}
    resultats = config["force_brute"]
    for ip in sorted(resultats):
        if resultats[ip]["attaque"]:
            heure = resultats[ip]["heure"].strftime("%H:%M:%S")
            alertes.append("Force brute depuis " + ip + " a " + heure)
    return alertes


def regle_trop_de_critiques(**config) -> list[str]:
    """Alerte si le nombre de logs CRITICAL depasse un seuil."""
    nb_critiques = config["stats"]["par_niveau"].get("CRITICAL", 0)
    seuil = config.get("seuil_critiques", 100)
    if nb_critiques > seuil:
        return [str(nb_critiques) + " logs CRITICAL (seuil : "
                + str(seuil) + ")"]
    return []


def apply_security_rules(*regles, **config) -> dict[str, list[str]]:
    """Applique toutes les regles recues et regroupe leurs alertes."""
    resultats = {}
    for regle in regles:
        if not callable(regle):
            print("Ignore (ce n'est pas une fonction) :",(regle))
            continue
        try:
            alertes = regle(**config)
        except KeyError as erreur:
            print("Regle", regle.__name__, "ignoree : il manque", erreur)
            continue
        resultats[regle.__name__] = alertes
    return resultats