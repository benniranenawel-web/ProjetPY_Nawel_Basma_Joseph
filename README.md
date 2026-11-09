# Moteur d'analyse de flux de logs

Projet final de Python — ING3, ECE Paris
Nawel, Basma, Joseph

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Tests](https://img.shields.io/badge/tests-18%20passed-brightgreen)

## Présentation

Ce projet est un outil en ligne de commande qui analyse des fichiers de logs
système et réseau. Il lit les fichiers ligne par ligne sans les charger
entièrement en mémoire, nettoie les données, calcule des statistiques et
détecte des comportements suspects :

- les adresses IP présentes dans une liste noire (blacklist) ;
- les attaques par force brute (plusieurs échecs de connexion consécutifs
  depuis la même IP).

## Prérequis

- Python 3.10 ou plus (nécessaire pour `match-case`)
- Git

## Installation

```powershell
git clone <url-du-depot>
cd Projet_ECE_Nawel_Basma_Joseph
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Utilisation

| Commande | Description |
|---|---|
| `python generer_donnees.py` | génère les fichiers de logs de test dans `data/` |
| `python generer_donnees.py --gros` | génère en plus un fichier d'un million de lignes |
| `python main.py` | lance l'analyse sur les fichiers de `data/` |
| `python main.py --flux` | lance l'analyse sur un flux de logs simulé |
| `python -m pytest -v` | lance les tests automatiques |

Le rapport d'audit des variables est écrit dans `output/audit.txt`.

## Structure du projet

```
Projet_ECE_Nawel_Basma_Joseph/
├── src/
│   ├── logs.py          lecture des fichiers (générateurs)
│   ├── transfo.py       transformation d'une ligne en dictionnaire
│   ├── filtres.py       filtrage, normalisation et routage des logs
│   ├── analyse.py       statistiques, ensembles d'IP, force brute
│   ├── regles.py        moteur de règles de sécurité
│   └── audit.py         audit des variables en mémoire
├── tests/
│   └── test_projet.py   tests automatiques (pytest)
├── data/                fichiers de logs de test et blacklist.txt
├── main.py              point d'entrée du programme
├── generer_donnees.py   génération du jeu de données
└── requirements.txt
```

## Fonctionnement

Chaque ligne traverse les étapes suivantes, une par une :

```
fichiers .log
  -> lecture (yield / yield from)            src/logs.py
  -> ligne -> dictionnaire + tuple           src/transfo.py
  -> nettoyage et filtrage (filter / map)    src/filtres.py
  -> statistiques et détection               src/analyse.py
  -> règles de sécurité                      src/regles.py
  -> affichage et audit                      main.py, src/audit.py
```

Les fichiers ne sont jamais chargés entièrement : `filter()` et `map()`
renvoient des itérateurs, donc chaque ligne est traitée puis oubliée avant de
lire la suivante.

## Format des logs

```
2026-11-03T09:00:01 | ERROR | 192.168.1.10:22/TCP | user=alice | {"event": "login_failed"}
```

Cinq champs séparés par `|` : horodatage, niveau (INFO, WARNING, ERROR,
CRITICAL), connexion (IP:port/protocole), utilisateur, message (JSON ou texte
brut).

## Jeu de données

Les logs sont fictifs et générés par `generer_donnees.py`. Une graine
aléatoire fixe permet d'obtenir toujours les mêmes fichiers.
Le fichier `serveur1.log` contient des cas de test ajoutés volontairement :

- une attaque par force brute (6 échecs consécutifs depuis `203.0.113.42`) ;
- un utilisateur qui échoue 4 fois, réussit, puis échoue 3 fois (pas d'attaque) ;
- une IP blacklistée active (`192.0.2.66`) ;
- des lignes mal formées ou invalides, qui doivent être rejetées.

La liste noire d'IP est dans `data/blacklist.txt` (une IP par ligne, les
lignes vides et les commentaires `#` sont ignorés).

## Notions Python utilisées

| Module | Notion | Fichier / fonction |
|---|---|---|
| 1 | `yield`, `yield from` | `logs.py` : `lire_fichier`, `lire_plusieurs_fichiers` |
| 1 | dictionnaire, tuple | `transfo.py` : `parser_ligne`, `lire_connexion` |
| 2 | `filter`, `lambda`, `map`, f-strings | `filtres.py` : `construire_pipeline`, `normaliser_log` |
| 2 | `match-case` | `filtres.py` : `router_log` |
| 3 | `set`, `frozenset`, opérations d'ensembles | `analyse.py` : `charger_blacklist`, `comparer_blacklist` |
| 3 | `defaultdict` | `analyse.py` : `analyser_logs` |
| 3 | `while`, `for`, `break`, `continue`, `else` | `analyse.py` : `detecter_force_brute` |
| 4 | `*args`, `**kwargs` | `regles.py` : `apply_security_rules` |
| 4 | `globals()`, `locals()` | `main.py` : `main` (appels), `audit.py` : `exporter_audit` |

## Résultats sur le jeu de test

| Indicateur | Valeur |
|---|---|
| Lignes lues | 2 022 |
| Logs valides | 1 918 |
| Lignes rejetées | 104 |
| IP blacklistées actives | 2 |
| Attaques par force brute détectées | 1 |

## Limites

- Les niveaux de gravité des logs de test sont tirés au hasard et ne
  correspondent pas toujours aux événements.
- La détection de force brute ne tient pas compte du temps écoulé entre deux
  tentatives.
- Le programme ne lit que le format de ligne décrit plus haut.