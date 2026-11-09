# ============================================================
# PROGRAMME PRINCIPAL : lance toute l'analyse des logs
# ============================================================
# Utilisation (dans PowerShell, depuis le dossier du projet) :
#   python main.py          -> analyse les fichiers du dossier data/
#   python main.py --flux   -> analyse un flux de logs simule en direct

# sys.argv : la liste des mots tapes apres "python" dans le terminal
import sys

# Module 1 : lecture des fichiers et flux simule
from src.logs import generer_logs, lire_plusieurs_fichiers
# Module 2 : nettoyage des logs (filter, map, lambda)
from src.filtres import construire_pipeline, creer_compteurs
# Module 3 : statistiques, ensembles, force brute
from src.analyse import analyser_logs, charger_blacklist, comparer_blacklist
from src.analyse import detecter_force_brute
# Module 4 : moteur de regles et audit
from src.regles import apply_security_rules, regle_blacklist
from src.regles import regle_force_brute, regle_trop_de_critiques
from src.audit import exporter_audit

# ---------------- Parametres du programme ----------------
# fichiers de logs a analyser
FICHIERS = ["data/serveur1.log", "data/serveur2.log"]
# fichier qui contient la liste noire d'IP (une IP par ligne)
FICHIER_BLACKLIST = "data/blacklist.txt"
# nombre d'echecs de connexion d'affilee pour parler d'attaque
SEUIL_ECHECS = 5
# nombre de logs CRITICAL a partir duquel on alerte
SEUIL_CRITIQUES = 100
# fichier ou on ecrit le rapport d'audit
FICHIER_AUDIT = "output/audit.txt"


def afficher_titre(titre: str) -> None:
    """Affiche un titre encadre de lignes de '='."""
    
    print()
    # "=" * 50 repete le caractere 50 fois
    print("=" * 50)
    print(titre)
    print("=" * 50)


def afficher_compteur(titre: str, compteur: dict) -> None:
    """Affiche un compteur, du plus grand au plus petit."""
    print()
    print(titre, ":")
    # on trie les couples (cle, valeur) selon la valeur x[1],
    # reverse=True pour avoir le plus grand en premier
    tri = sorted(compteur.items(), key=lambda x: x[1], reverse=True)
    # on affiche chaque couple, la cle alignee sur 20 caracteres
    for cle, valeur in tri:
        print("  ", cle.ljust(20), valeur)


def afficher_lignes_traitees(compteurs: dict, nb_valides: int) -> None:
    """Affiche le bilan des lignes lues et verifie que le compte est juste."""
    afficher_titre("LIGNES TRAITEES")
    print("Lignes lues       :", compteurs["lues"])
    print("Lignes vides      :", compteurs["vides"])
    print("Lignes fausses    :", compteurs["fausses"])
    print("Lignes invalides  :", compteurs["invalides"])
    print("Logs valides      :", nb_valides)
    # chaque ligne lue doit etre tombee dans une seule categorie
    total = (compteurs["vides"] + compteurs["fausses"]
             + compteurs["invalides"] + nb_valides)
    if total == compteurs["lues"]:
        print("Verification      : OK (lues = vides + fausses + invalides + valides)")
    else:
        print("Verification      : ERREUR, le compte ne tombe pas juste")


def main() -> None:
    """Enchaine toutes les etapes du projet et affiche les resultats."""
    # ---- 1) Choix de la source des lignes ----
    # si l'utilisateur a tape --flux, on simule des logs en direct
    if "--flux" in sys.argv:
        print("Source : flux simule de 3000 lignes")
        # generateur : les lignes sont creees une par une
        lignes = generer_logs(3000, graine=3, scenarios=True)
    # sinon on lit les fichiers du dossier data/
    else:
        print("Source :", ", ".join(FICHIERS))
        # generateur : les fichiers sont lus ligne par ligne
        lignes = lire_plusieurs_fichiers(FICHIERS)   

    # ---- 2) Pipeline puis statistiques (Modules 2 et 3) ----
    # nettoyage des lignes (rien n'est encore calcule)
    compteurs = creer_compteurs()
    logs = construire_pipeline(lignes, compteurs)
    # un seul parcours des logs pour tout compter
    # (c'est aussi ce parcours qui remplit les compteurs)
    stats = analyser_logs(logs)

    # si aucun log valide, on arrete en expliquant pourquoi
    if stats["nb_logs"] == 0:
        print("Aucun log valide.")
        print("Lancez d'abord : python generer_donnees.py")
        return

    # ---- 3) Ensembles et force brute (Module 3) ----
    # liste noire d'IP : frozenset car elle ne doit jamais etre modifiee
    blacklist = charger_blacklist(FICHIER_BLACKLIST)
    # fichier absent ou vide : on previent et on continue sans blacklist
    if not blacklist:
        print("Attention : blacklist vide, aucune IP ne sera signalee.")
    ensembles = comparer_blacklist(stats["ips_actives"],
                                   stats["ips_erreur"], blacklist)
    force_brute = detecter_force_brute(stats["tentatives"], SEUIL_ECHECS)

    # ---- 4) Moteur de regles (Module 4) ----
    # *args : les fonctions de regle (sans parentheses !)
    # **kwargs : les donnees et parametres dont elles ont besoin
    alertes = apply_security_rules(
        regle_blacklist,
        regle_force_brute,
        regle_trop_de_critiques,
        stats=stats,
        ensembles=ensembles,
        force_brute=force_brute,
        seuil_critiques=SEUIL_CRITIQUES,)

    # ---- 5) Affichage des resultats ----
    afficher_lignes_traitees(compteurs, stats["nb_logs"])

    afficher_titre("STATISTIQUES")
    print("Nombre de logs valides :", stats["nb_logs"])
    afficher_compteur("Par niveau", stats["par_niveau"])
    afficher_compteur("Par categorie", stats["par_categorie"])
    afficher_compteur("Par type de connexion", stats["par_connexion"])
    afficher_compteur("Par utilisateur", stats["par_user"])

    afficher_titre("ENSEMBLES D'IP")
    # sorted() transforme le set en liste triee, plus lisible
    print("IP actives   :", sorted(stats["ips_actives"]))
    print("IP en erreur :", sorted(stats["ips_erreur"]))
    print("Blacklist    :", sorted(blacklist))
    # une ligne par resultat d'operation d'ensembles
    for nom in ensembles:
        print(nom.ljust(22), ":", sorted(ensembles[nom]))

    afficher_titre("FORCE BRUTE (seuil = " + str(SEUIL_ECHECS) + ")")
    # une ligne par IP, avec son etat
    for ip in sorted(force_brute):
        if force_brute[ip]["attaque"]:
            etat = "ATTAQUE"
        else:
            etat = "ok"
        print(ip.ljust(15), etat.ljust(8), "max d'echecs d'affilee :",
              force_brute[ip]["max_echecs"])

    afficher_titre("ALERTES")
    # alertes = {nom de la regle: liste d'alertes}
    for nom_regle in alertes:
        print("[" + nom_regle + "]")
        for alerte in alertes[nom_regle]:
            print("  -", alerte)

    # ---- 6) Audit (Module 4) ----
    # globals() : variables du fichier main.py
    # locals()  : variables de la fonction main()
    exporter_audit(FICHIER_AUDIT, globals(), locals())
    print()
    print("Rapport d'audit ecrit dans", FICHIER_AUDIT)


# ce bloc s'execute seulement si on lance directement : python main.py
# (et pas si un autre fichier fait "import main")
if __name__ == "__main__":
    main()
