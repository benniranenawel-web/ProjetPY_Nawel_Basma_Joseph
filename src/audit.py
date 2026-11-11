# MODULE 4 : audit des variables en memoire

# globals= un dico de variables globales du fichier(imports, fonctions, constantes)
#
# locals= un dico de variables de la fonction


# pr creer le dossier du rapport
import os


LONGUEUR_MAX = 60


def decrire_variables(variables: dict) -> list[str]:
    """Renv une ligne de texte par variable (nom, type, apercu)"""
    lignes = []
    # sorted=ordre alphabetique
    for nom in sorted(variables):
        # les __xxx__  on les saute
        if nom.startswith("__"):
            continue
        valeur = variables[nom]
        type_nom = type(valeur).__name__
        apercu = repr(valeur)
        if len(apercu) > LONGUEUR_MAX:
            apercu = apercu[:LONGUEUR_MAX] + "..."

        ligne = nom.ljust(25) + " " + type_nom.ljust(15) + " " + apercu
        lignes.append(ligne)
    return lignes


def exporter_audit(chemin: str, variables_globales: dict,
                   variables_locales: dict) -> None:
    """Ecrit le rapport d'audit (globals et locals) dans un fichier."""
    dossier = os.path.dirname(chemin)
    if dossier != "":
        os.makedirs(dossier, exist_ok=True)
    with open(chemin, "w", encoding="utf-8") as fichier:
        fichier.write("=== VARIABLES GLOBALES (globals()) ===\n")
        for ligne in decrire_variables(variables_globales):
            fichier.write(ligne + "\n")
        fichier.write("\n=== VARIABLES LOCALES (locals()) ===\n")
        for ligne in decrire_variables(variables_locales):
            fichier.write(ligne + "\n")
