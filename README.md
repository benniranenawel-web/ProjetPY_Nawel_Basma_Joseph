# ProjetPY_Nawel_Basma_Joseph
<div align="center">

# 🌸 Moteur d'analyse de logs sécurisé 🌸

**Projet final Python — ING3 ECE**

*Nawel · Basma · Joseph*

![Python](https://img.shields.io/badge/Python-3.10%2B-ff69b4?style=for-the-badge&logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-15%20passed-ff1493?style=for-the-badge&logo=pytest&logoColor=white)
![Mémoire](https://img.shields.io/badge/RAM-0%2C04%20Mo-ffb6c1?style=for-the-badge)
![Statut](https://img.shields.io/badge/statut-termin%C3%A9-db7093?style=for-the-badge)

</div>

---

## 💡 Le projet en bref

Des serveurs écrivent des **millions de lignes de logs** par jour. Notre programme :

- 📖 **lit** les fichiers ligne par ligne, sans jamais les charger entièrement en mémoire ;
- 🧹 **nettoie** les lignes (vides, mal écrites, invalides) ;
- 📊 **compte** les logs par niveau, par utilisateur, par type de connexion ;
- 🚨 **détecte** les IP blacklistées et les **attaques par force brute**.

---

## 🔄 Le trajet d'une ligne

```mermaid
flowchart LR
    A[📁 Fichiers .log] --> B[📖 logs.py<br/>yield / yield from]
    B --> C[🔧 transfo.py<br/>dict + tuple]
    C --> D[🧹 filtres.py<br/>filter / map / match-case]
    D --> E[📊 analyse.py<br/>set / defaultdict]
    E --> F[🚨 regles.py<br/>*args / **kwargs]
    F --> G[🔍 audit.py<br/>globals / locals]

    style A fill:#ffe4ec,stroke:#ff69b4,color:#000
    style B fill:#ffb6c1,stroke:#ff69b4,color:#000
    style C fill:#ffb6c1,stroke:#ff69b4,color:#000
    style D fill:#ff9ec4,stroke:#ff1493,color:#000
    style E fill:#ff9ec4,stroke:#ff1493,color:#000
    style F fill:#ff69b4,stroke:#c71585,color:#fff
    style G fill:#ff69b4,stroke:#c71585,color:#fff
```

---

## 🚀 Installation

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## ▶️ Utilisation

| Commande | Ce que ça fait |
|---|---|
| `python generer_donnees.py` | 🌱 crée les fichiers de logs de test |
| `python generer_donnees.py --gros` | 🐘 crée aussi un fichier d'1 million de lignes |
| `python main.py` | 🔍 lance l'analyse complète |
| `python main.py --flux` | 🌊 analyse un flux de logs simulé en direct |
| `python -m pytest -v` | ✅ lance les tests automatiques |

---

## 📂 Organisation

```
📦 Projet_ECE_Nawel_Basma_Joseph
 ┣ 📂 src
 ┃ ┣ 📜 logs.py        → lecture des fichiers
 ┃ ┣ 📜 transfo.py     → ligne → dictionnaire
 ┃ ┣ 📜 filtres.py     → nettoyage et tri
 ┃ ┣ 📜 analyse.py     → stats et force brute
 ┃ ┣ 📜 regles.py      → moteur de règles
 ┃ ┗ 📜 audit.py       → audit de la mémoire
 ┣ 📂 data             → logs de test
 ┣ 📂 tests            → tests automatiques
 ┣ 📜 main.py          → programme principal
 ┗ 📜 generer_donnees.py
```

---

## 🎀 Les notions du sujet dans notre code

| Module | Notion | Où |
|---|---|---|
| 1️⃣ | `yield` | `src/logs.py` → `lire_fichier` |
| 1️⃣ | `yield from` | `src/logs.py` → `lire_plusieurs_fichiers` |
| 1️⃣ | dictionnaire + tuple (IP, Port, Protocole) | `src/transfo.py` → `parser_ligne`, `lire_connexion` |
| 2️⃣ | `filter` + `lambda`, `filter(None, ...)` | `src/filtres.py` → `construire_pipeline` |
| 2️⃣ | `map` + f-strings | `src/filtres.py` → `normaliser_log` |
| 2️⃣ | `match-case` | `src/filtres.py` → `router_log` |
| 3️⃣ | `set`, `frozenset`, `\|` `&` `-` `^` | `src/analyse.py` → `comparer_blacklist` |
| 3️⃣ | `defaultdict` | `src/analyse.py` → `analyser_logs` |
| 3️⃣ | `while` + `for` + `break` + `continue` + `else` | `src/analyse.py` → `detecter_force_brute` |
| 4️⃣ | `apply_security_rules(*args, **kwargs)` | `src/regles.py` |
| 4️⃣ | `globals()` / `locals()` | `src/audit.py` → `exporter_audit` |

---

## 📊 Résultats sur nos données de test

| | |
|---|---|
| 📄 Lignes lues | **2 022** |
| ✅ Logs valides | **1 918** |
| 🗑️ Lignes rejetées | **104** |
| ⛔ IP blacklistées actives | **2** (`192.0.2.66`, `203.0.113.42`) |
| 🚨 Attaque par force brute | **1** (`203.0.113.42`) |
| 🧠 Mémoire pour 1 million de lignes | **~0,04 Mo** (contre ~124 Mo avec `readlines()`) |

---

<div align="center">

💖 *Fait avec amour (et beaucoup de `print`) par Nawel, Basma et Joseph* 💖

</div>