# ============================================================
# MODULE 4 : audit des variables en memoire
# (globals() et locals())
# ============================================================
# globals() : dictionnaire des variables globales d'un fichier
#             (imports, fonctions, constantes)
# locals()  : dictionnaire des variables de la fonction en cours
# On recoit ces deux dictionnaires et on ecrit un rapport texte.

# os : pour creer le dossier du rapport s'il n'existe pas
import os

# au-dela de cette longueur, on coupe l'apercu d'une variable
LONGUEUR_MAX = 60


def decrire_variables(variables: dict) -> list[str]:
    """Renvoie une ligne de texte par variable : nom, type, apercu."""
    # liste des lignes du rapport
    lignes = []
    # sorted() : variables dans l'ordre alphabetique
    for nom in sorted(variables):
        # les noms en __xxx__ sont internes a Python : on les saute
        if nom.startswith("__"):
            continue
        # la valeur de la variable
        valeur = variables[nom]
        # le nom de son type, ex : "int", "dict", "function"
        type_nom = type(valeur).__name__
        # repr() donne une representation texte de la valeur
        apercu = repr(valeur)
        # si c'est trop long, on coupe et on ajoute "..."
        if len(apercu) > LONGUEUR_MAX:
            apercu = apercu[:LONGUEUR_MAX] + "..."
        # ljust(25) ajoute des espaces jusqu'a 25 caracteres
        # pour que les colonnes soient bien alignees
        ligne = nom.ljust(25) + " " + type_nom.ljust(15) + " " + apercu
        lignes.append(ligne)
    # on renvoie toutes les lignes
    return lignes


def exporter_audit(chemin: str, variables_globales: dict,
                   variables_locales: dict) -> None:
    """Ecrit le rapport d'audit (globals et locals) dans un fichier."""
    # dossier du fichier, ex : "output" pour "output/audit.txt"
    dossier = os.path.dirname(chemin)
    # on cree ce dossier s'il n'existe pas (et s'il y en a un)
    if dossier != "":
        os.makedirs(dossier, exist_ok=True)
    # "w" : on ecrit (le fichier est remplace s'il existait)
    with open(chemin, "w", encoding="utf-8") as fichier:
        # partie 1 : les variables globales
        fichier.write("=== VARIABLES GLOBALES (globals()) ===\n")
        for ligne in decrire_variables(variables_globales):
            fichier.write(ligne + "\n")
        # partie 2 : les variables locales
        fichier.write("\n=== VARIABLES LOCALES (locals()) ===\n")
        for ligne in decrire_variables(variables_locales):
            fichier.write(ligne + "\n")