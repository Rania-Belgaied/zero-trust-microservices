"""
============================================================
  AHP — Analytic Hierarchy Process
  Méthode : Moyenne Géométrique (Saaty, 1980)

  Projet PFA — Zero-Trust MAS Microservices Security
  RT4 2026 — Belgaied, Elhaj Arbi, Ayeb

  Référence : Saaty, T.L. (1980). The Analytic Hierarchy
  Process. McGraw-Hill, New York.
============================================================

  Calcule les poids subjectifs (w_AHP) des 5 composantes
  de la formule de score de sécurité :

      S = w1·C + w2·I + w3·B + w4·P + w5·R

  à partir d'une matrice de comparaison par paires fondée
  sur le NIST SP 800-207 et les CIS Controls v8.
"""

import numpy as np


# ─────────────────────────────────────────────────────────────
# PARAMÈTRES
# ─────────────────────────────────────────────────────────────

COMPONENTS = ["C", "I", "B", "P", "R"]

# Seuil de cohérence de Saaty — la matrice est acceptée si CR < 0.10
CR_THRESHOLD = 0.10

# Random Index de Saaty (valeurs empiriques pour n = 1 à 10)
RI_TABLE = {
    1: 0.00, 2: 0.00, 3: 0.58, 4: 0.90,
    5: 1.12, 6: 1.24, 7: 1.32, 8: 1.41,
    9: 1.45, 10: 1.49
}


# ─────────────────────────────────────────────────────────────
# ÉTAPE 1 — Construction de la matrice de comparaison
# ─────────────────────────────────────────────────────────────

def build_ahp_matrix() -> np.ndarray:
    """
    Matrice de comparaison par paires 5×5.
    Ordre des lignes/colonnes : C, I, B, P, R

    Règle de lecture : m[i][j] = "combien de fois la composante i
    est-elle plus importante que la composante j ?"

    Si m[i][j] = x  →  m[j][i] = 1/x  (réciprocité obligatoire)
    La diagonale est toujours 1  (composante comparée à elle-même)

    Justification de chaque valeur :
    ┌─────────┬───────────────────────────────────────────────────────────┐
    │ C vs I=2│ mTLS rompu = tout le trafic exposé (urgence immédiate)    │
    │         │ OPA I = compromission de chemins spécifiques (moins large)│
    ├─────────┼───────────────────────────────────────────────────────────┤
    │ C vs B=1│ Co-égaux : canal sécurisé ET intérieur surveillé sont     │
    │         │ deux piliers directs du Zero-Trust (NIST SP 800-207 §2.1) │
    ├─────────┼───────────────────────────────────────────────────────────┤
    │ C vs P=3│ Rupture mTLS = urgence active ; non-conformité OPA =      │
    │         │ risque potentiel (peut être un faux positif de config)     │
    ├─────────┼───────────────────────────────────────────────────────────┤
    │ C vs R=5│ Confidentialité >> Disponibilité en Zero-Trust            │
    │         │ (NIST SP 800-207 ne cite pas R comme critère ZT primaire) │
    ├─────────┼───────────────────────────────────────────────────────────┤
    │ I vs B  │ B > I : Falco détecte une intrusion ACTIVE (syscalls en   │
    │ = 1/2   │ cours) ; OPA I détecte des violations déjà loggées        │
    ├─────────┼───────────────────────────────────────────────────────────┤
    │ I vs P=2│ Violations actives (I) > non-conformité structurelle (P)  │
    ├─────────┼───────────────────────────────────────────────────────────┤
    │ I vs R=4│ Intégrité des accès >> Disponibilité applicative          │
    ├─────────┼───────────────────────────────────────────────────────────┤
    │ B vs P=3│ Shell dans conteneur = intrusion active ; P = conformité  │
    │         │ structurelle pouvant être un artefact de configuration     │
    ├─────────┼───────────────────────────────────────────────────────────┤
    │ B vs R=5│ Intrusion active >> Instabilité applicative               │
    ├─────────┼───────────────────────────────────────────────────────────┤
    │ P vs R=2│ Conformité sécurité > Disponibilité                       │
    └─────────┴───────────────────────────────────────────────────────────┘
    """
    #         C      I      B      P      R
    m = np.array([
        [1,    2,    1,    3,    5   ],  # C
        [1/2,  1,    1/2,  2,    4   ],  # I
        [1,    2,    1,    3,    5   ],  # B
        [1/3,  1/2,  1/3,  1,    2   ],  # P
        [1/5,  1/4,  1/5,  1/2,  1   ],  # R
    ])
    return m


# ─────────────────────────────────────────────────────────────
# ÉTAPE 2 à 8 — Calcul des poids et vérification CR
# ─────────────────────────────────────────────────────────────

def compute_ahp_weights(matrix: np.ndarray):
    """
    Calcule les poids AHP par la méthode de la moyenne géométrique.

    Retourne un dictionnaire avec tous les résultats intermédiaires
    pour la transparence et la traçabilité académique.

    ── Étape 2 ── Moyenne géométrique de chaque ligne
        GM_i = (a_i1 × a_i2 × ... × a_in) ^ (1/n)

    ── Étape 3 ── Total des moyennes géométriques
        Total = Σ GM_i

    ── Étape 4 ── Priorités (poids normalisés)
        Priority_i = GM_i / Total

    ── Étape 5 ── Somme de chaque colonne
        Col_j = Σ_i a_ij

    ── Étape 6 ── Lambda max
        λmax = Σ_i (Priority_i × Col_i)

    ── Étape 7 ── Consistency Index
        CI = (λmax - n) / (n - 1)

    ── Étape 8 ── Consistency Ratio
        CR = CI / RI[n]
    """
    n = matrix.shape[0]

    # ── Étape 2 : Moyenne géométrique de chaque ligne ──────────
    # np.prod(matrix, axis=1) = produit de tous les éléments de chaque ligne
    # ** (1/n)               = racine n-ième du produit
    geo_means = np.prod(matrix, axis=1) ** (1.0 / n)

    # ── Étape 3 : Total des moyennes géométriques ──────────────
    total_gm = geo_means.sum()

    # ── Étape 4 : Priorités ────────────────────────────────────
    priorities = geo_means / total_gm

    # ── Étape 5 : Somme de chaque colonne ──────────────────────
    col_sums = matrix.sum(axis=0)

    # ── Étape 6 : Lambda max ───────────────────────────────────
    # Pour chaque composante i : Priority_i × Col_i, puis somme de tout
    lambda_max = np.sum(priorities * col_sums)

    # ── Étape 7 : Consistency Index ────────────────────────────
    CI = (lambda_max - n) / (n - 1)

    # ── Étape 8 : Consistency Ratio ────────────────────────────
    RI = RI_TABLE[n]
    CR = CI / RI if RI > 0 else 0.0

    return {
        "geo_means":   geo_means,
        "total_gm":    total_gm,
        "priorities":  priorities,
        "col_sums":    col_sums,
        "lambda_max":  lambda_max,
        "CI":          CI,
        "RI":          RI,
        "CR":          CR,
        "n":           n,
        "is_consistent": CR < CR_THRESHOLD
    }


# ─────────────────────────────────────────────────────────────
# AFFICHAGE DU RAPPORT COMPLET
# ─────────────────────────────────────────────────────────────

def print_ahp_report(matrix: np.ndarray, results: dict):
    n = results["n"]
    sep = "═" * 62

    print(f"\n{sep}")
    print("  AHP — RAPPORT COMPLET (Méthode Moyenne Géométrique)")
    print(sep)

    # Matrice originale
    print("\n  ── Matrice de comparaison par paires ──\n")
    header = f"  {'':>4}" + "".join(f"{c:>9}" for c in COMPONENTS)
    print(header)
    print("  " + "─" * 50)
    for i, name in enumerate(COMPONENTS):
        row = "".join(f"{matrix[i,j]:>9.4f}" for j in range(n))
        print(f"  {name:>4}{row}")

    # Étape 2 & 3 : Moyennes géométriques
    print("\n  ── Étape 2 & 3 : Moyennes géométriques ──\n")
    print(f"  {'Composante':>12} {'Produit ligne':>16} {'GM = Prod^(1/5)':>18}")
    print("  " + "─" * 50)
    for i, name in enumerate(COMPONENTS):
        prod = np.prod(matrix[i])
        gm   = results["geo_means"][i]
        print(f"  {name:>12} {prod:>16.6f} {gm:>18.6f}")
    print(f"\n  Total des GM = {results['total_gm']:.6f}")

    # Étape 4 : Priorités
    print("\n  ── Étape 4 : Priorités (poids AHP) ──\n")
    print(f"  {'Composante':>12} {'GM':>10} {'Priority = GM/Total':>22} {'Barre':>6}")
    print("  " + "─" * 56)
    for i, name in enumerate(COMPONENTS):
        gm   = results["geo_means"][i]
        prio = results["priorities"][i]
        bar  = "█" * int(prio * 40)
        print(f"  {name:>12} {gm:>10.6f} {prio:>22.4f}  {bar}")
    print(f"\n  Somme des priorités = {results['priorities'].sum():.4f}  ✓ (doit être 1.0)")

    # Étape 5 : Sommes des colonnes
    print("\n  ── Étape 5 : Somme de chaque colonne ──\n")
    for j, name in enumerate(COMPONENTS):
        print(f"  Col_{name} = {results['col_sums'][j]:.4f}")

    # Étape 6 : Lambda max
    print("\n  ── Étape 6 : Lambda max ──\n")
    print(f"  {'Composante':>12} {'Priority':>12} {'Col_sum':>12} {'Priority × Col':>16}")
    print("  " + "─" * 56)
    total_check = 0
    for i, name in enumerate(COMPONENTS):
        p   = results["priorities"][i]
        c   = results["col_sums"][i]
        val = p * c
        total_check += val
        print(f"  {name:>12} {p:>12.4f} {c:>12.4f} {val:>16.4f}")
    print(f"  {'λmax':>12} {'':>12} {'':>12} {results['lambda_max']:>16.4f}")

    # Étapes 7 & 8 : CI et CR
    print("\n  ── Étapes 7 & 8 : CI et CR ──\n")
    print(f"  n         = {n}")
    print(f"  λmax      = {results['lambda_max']:.4f}")
    print(f"  CI = (λmax - n) / (n-1) = ({results['lambda_max']:.4f} - {n}) / {n-1} = {results['CI']:.4f}")
    print(f"  RI        = {results['RI']}  (table Saaty, n={n})")
    print(f"  CR = CI / RI = {results['CI']:.4f} / {results['RI']} = {results['CR']:.4f}")

    if results["is_consistent"]:
        print(f"\n  ✓ CR = {results['CR']:.4f} < {CR_THRESHOLD} → Matrice COHÉRENTE")
        print(f"    Les poids AHP sont valides et peuvent être utilisés.")
    else:
        print(f"\n  ✗ CR = {results['CR']:.4f} ≥ {CR_THRESHOLD} → Matrice INCOHÉRENTE")
        print(f"    Révisez la matrice de comparaison.")

    print(f"\n{sep}\n")


# ─────────────────────────────────────────────────────────────
# POINT D'ENTRÉE
# ─────────────────────────────────────────────────────────────

def run_ahp() -> dict:
    matrix  = build_ahp_matrix()
    results = compute_ahp_weights(matrix)
    print_ahp_report(matrix, results)
    return results


if __name__ == "__main__":
    results = run_ahp()
    print("  Poids AHP finals :")
    for name, w in zip(COMPONENTS, results["priorities"]):
        print(f"    w_{name} = {w:.4f}")