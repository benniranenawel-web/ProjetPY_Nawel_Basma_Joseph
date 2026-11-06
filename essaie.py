# Fichier d'essai pour verifier le Module 4 (a supprimer a la fin)

from src.logs import lire_plusieurs_fichiers
from src.filtres import construire_pipeline
from src.analyse import analyser_logs, comparer_blacklist
from src.analyse import detecter_force_brute
from src.regles import apply_security_rules, regle_blacklist
from src.regles import regle_force_brute, regle_trop_de_critiques
from src.audit import exporter_audit

# on prepare les donnees comme dans les modules precedents
fichiers = ["data/serveur1.log", "data/serveur2.log"]
stats = analyser_logs(construire_pipeline(lire_plusieurs_fichiers(fichiers)))
bl = frozenset({"203.0.113.42", "192.0.2.66", "192.0.2.99"})
ens = comparer_blacklist(stats["ips_actives"], stats["ips_erreur"], bl)
fb = detecter_force_brute(stats["tentatives"], 5)

print("--- Test 1 : le moteur avec 3 regles ---")
alertes = apply_security_rules(regle_blacklist, regle_force_brute,
                               regle_trop_de_critiques, stats=stats,
                               ensembles=ens, force_brute=fb,
                               seuil_critiques=100)
for nom in alertes:
    print(nom, ":", alertes[nom])

print()
print("--- Test 2 : quelque chose qui n'est pas une fonction ---")
print(apply_security_rules(regle_blacklist, "coucou", ensembles=ens))

print()
print("--- Test 3 : un parametre manquant ---")
print(apply_security_rules(regle_force_brute))

print()
print("--- Test 4 : seuil a 500 ---")
print(apply_security_rules(regle_trop_de_critiques, stats=stats,
                           seuil_critiques=500))

print()
print("--- Test 5 : audit ---")
exporter_audit("output/audit_test.txt", globals(), locals())
print("Rapport ecrit dans output/audit_test.txt")
