"""
============================================================
  EWM — Entropy Weight Method
  Méthode : Entropie de Shannon (1948)

  Projet PFA — Zero-Trust MAS Microservices Security
  RT4 2026 — Belgaied, Elhaj Arbi, Ayeb

  Référence : Shannon, C.E. (1948). A Mathematical Theory
  of Communication. Bell System Technical Journal, 27, 379–423.
============================================================

  Calcule les poids objectifs (w_EWM) des 5 composantes
  à partir du dataset réel collecté par les LSA.

  Principe : une composante qui varie beaucoup dans les données
  porte plus d'information utile → elle reçoit un poids plus élevé.
"""

import numpy as np
import pandas as pd


# ─────────────────────────────────────────────────────────────
# PARAMÈTRES
# ─────────────────────────────────────────────────────────────

COMPONENTS   = ["C", "I", "B", "P", "R"]
DATASET_PATH = "../dataset/security_dataset.csv"


# ─────────────────────────────────────────────────────────────
# ÉTAPES 1 À 5 — Calcul des poids EWM
# ─────────────────────────────────────────────────────────────

def compute_ewm_weights(df: pd.DataFrame):
    """
    Calcule les poids EWM en 5 étapes.

    ── Étape 1 ── Normalisation min-max
        x_norm_ij = (x_ij - min_j) / (max_j - min_j)
        Projette chaque composante dans [0, 1]

    ── Étape 2 ── Proportion p_ij
        p_ij = x_norm_ij / Σ_i x_norm_ij
        Part relative de chaque échantillon dans sa composante

    ── Étape 3 ── Entropie de Shannon
        e_j = -(1/ln(n)) × Σ_i [ p_ij × ln(p_ij) ]
        Mesure le désordre informationnel de chaque composante
        Proche de 1.0 → peu de variabilité → peu d'info utile

    ── Étape 4 ── Degré de divergence
        d_j = 1 - e_j
        Mesure l'utilité discriminante de chaque composante

    ── Étape 5 ── Poids EWM
        w_j = d_j / Σ_j d_j
        Normalise les divergences pour obtenir des poids (somme = 1)
    """
    X = df[COMPONENTS].values.astype(float)
    n_samples, n_criteria = X.shape

    # ── Étape 1 : Normalisation min-max ────────────────────────
    X_min = X.min(axis=0)
    X_max = X.max(axis=0)
    # Évite la division par 0 si une colonne est constante
    denom  = np.where((X_max - X_min) == 0, 1e-10, X_max - X_min)
    X_norm = (X - X_min) / denom

    # ── Étape 2 : Proportion p_ij ──────────────────────────────
    col_sums = X_norm.sum(axis=0)
    col_sums = np.where(col_sums == 0, 1e-10, col_sums)
    P = X_norm / col_sums

    # ── Étape 3 : Entropie de Shannon ──────────────────────────
    # k = 1/ln(n) : facteur de normalisation pour que e ∈ [0, 1]
    k = 1.0 / np.log(n_samples)
    # Remplace les 0 par un epsilon pour éviter ln(0) = -inf
    P_safe  = np.where(P == 0, 1e-10, P)
    entropy = -k * (P_safe * np.log(P_safe)).sum(axis=0)

    # ── Étape 4 : Degré de divergence ──────────────────────────
    divergence = 1.0 - entropy

    # ── Étape 5 : Poids EWM ────────────────────────────────────
    total_div  = divergence.sum()
    weights_ewm = divergence / total_div

    return {
        "X_min":       X_min,
        "X_max":       X_max,
        "entropy":     entropy,
        "divergence":  divergence,
        "total_div":   total_div,
        "weights":     weights_ewm,
        "n_samples":   n_samples,
        "k":           k
    }


# ─────────────────────────────────────────────────────────────
# AFFICHAGE DU RAPPORT COMPLET
# ─────────────────────────────────────────────────────────────

def print_ewm_report(df: pd.DataFrame, results: dict):
    sep = "═" * 62

    print(f"\n{sep}")
    print("  EWM — RAPPORT COMPLET (Entropie de Shannon)")
    print(sep)

    print(f"\n  Dataset : {results['n_samples']} échantillons")
    print(f"  Facteur k = 1/ln(n) = 1/ln({results['n_samples']}) = {results['k']:.6f}")

    # Étape 1 : Plages des composantes
    print("\n  ── Étape 1 : Plages min-max dans le dataset ──\n")
    print(f"  {'Composante':>12} {'Min':>10} {'Max':>10} {'Amplitude':>12}")
    print("  " + "─" * 48)
    for i, name in enumerate(COMPONENTS):
        mn  = results["X_min"][i]
        mx  = results["X_max"][i]
        amp = mx - mn
        print(f"  {name:>12} {mn:>10.4f} {mx:>10.4f} {amp:>12.4f}")

    # Étapes 3, 4, 5 : Entropie, divergence, poids
    print("\n  ── Étapes 3, 4, 5 : Entropie → Divergence → Poids ──\n")
    print(f"  {'Composante':>12} {'Entropie e_j':>14} {'Divergence d_j':>16} {'Poids EWM':>12}")
    print("  " + "─" * 58)
    for i, name in enumerate(COMPONENTS):
        e = results["entropy"][i]
        d = results["divergence"][i]
        w = results["weights"][i]
        print(f"  {name:>12} {e:>14.6f} {d:>16.6f} {w:>12.4f}")
    print(f"  {'Total':>12} {'':>14} {results['total_div']:>16.6f} {results['weights'].sum():>12.4f}")

    # Interprétation
    print("\n  ── Interprétation ──\n")
    sorted_idx = np.argsort(results["entropy"])
    print("  Du plus informatif au moins informatif :")
    for rank, idx in enumerate(sorted_idx, 1):
        name = COMPONENTS[idx]
        e    = results["entropy"][idx]
        w    = results["weights"][idx]
        note = ""
        if e > 0.995:
            note = "← faible variabilité dans le dataset"
        print(f"    {rank}. {name} : entropie={e:.6f}  poids={w:.4f}  {note}")

    print(f"\n  Note : toutes les entropies sont proches de 1.0")
    print(f"  C'est cohérent avec un système de détection GRADUELLE :")
    print(f"  les composantes varient peu — intentionnellement.")
    print(f"  La faible variabilité de C reflète une limitation du")
    print(f"  dataset mTLS, pas l'importance réelle de la composante.")

    print(f"\n{sep}\n")


# ─────────────────────────────────────────────────────────────
# POINT D'ENTRÉE
# ─────────────────────────────────────────────────────────────

def run_ewm() -> dict:
    df      = pd.read_csv(DATASET_PATH)
    results = compute_ewm_weights(df)
    print_ewm_report(df, results)
    return results


if __name__ == "__main__":
    results = run_ewm()
    print("  Poids EWM finals :")
    for name, w in zip(COMPONENTS, results["weights"]):
        print(f"    w_{name} = {w:.4f}")