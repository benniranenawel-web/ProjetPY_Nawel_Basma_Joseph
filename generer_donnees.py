# Cree les fichiers de logs de test dans le dossier data/
#   python generer_donnees.py         -> les 2 fichiers de test
#   python generer_donnees.py --gros  -> + un fichier d'1 million de lignes

import os
import sys

from src.logs import creer_fichier_test

os.makedirs("data", exist_ok=True)

# serveur1 contient les cas de test (attaque, blacklist, lignes fausses)
creer_fichier_test("data/serveur1.log", 1000, graine=1, scenarios=True)
creer_fichier_test("data/serveur2.log", 1000, graine=3)
print("Fichiers crees : data/serveur1.log et data/serveur2.log")

# si l'utilisateur a tape --gros apres le nom du script...
if "--gros" in sys.argv:
    # ...on cree aussi un gros fichier d'1 million de lignes (graine 4)
    # il sert a montrer que nos generateurs ne remplissent pas la RAM
    # (1_000_000 = 1000000, les _ rendent le nombre plus lisible)
    creer_fichier_test("data/gros_fichier.log", 1_000_000, graine=4)
    # message pour dire que le gros fichier est cree
    print("Fichier cree : data/gros_fichier.log")
# sinon, on lui explique comment creer le gros fichier
else:
    print("Astuce : tapez 'python generer_donnees.py --gros' pour creer")
    print("aussi un fichier d'1 million de lignes (test de memoire).")