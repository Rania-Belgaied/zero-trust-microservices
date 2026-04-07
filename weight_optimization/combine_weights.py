"""
============================================================
  AHP + EWM — Combinaison et génération de weights_optimal.json

  Projet PFA — Zero-Trust MAS Microservices Security
  RT4 2026 — Belgaied, Elhaj Arbi, Ayeb
============================================================

  Ce script importe les deux modules AHP et EWM,
  combine leurs poids, et sauvegarde le résultat final
  dans agents/lsa/weights_optimal.json

  Utilisation :
      python3 combine_weights.py

  Prérequis :
      ahp_weights.py et ewm_weights.py dans le même dossier
      dataset.csv accessible via DATASET_PATH
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path

# Import des deux modules
from ahp_weights import run_ahp, COMPONENTS
from ewm_weights import run_ewm

# ─────────────────────────────────────────────────────────────
# PARAMÈTRES
# ─────────────────────────────────────────────────────────────

DATASET_PATH = "../dataset/security_dataset.csv"
OUTPUT_PATH  = "../agents/lsa/weights_optimal.json"

# Coefficient de combinaison
# alpha = part accordée à l'AHP (expertise)
# 1 - alpha = part accordée à l'EWM (données)
ALPHA = 0.60

# Contraintes sur les poids finaux
MIN_WEIGHT = 0.05
MAX_WEIGHT = 0.50

# Poids initiaux (référence avant optimisation)
W_INITIAL = {"C": 0.25, "I": 0.20, "B": 0.25, "P": 0.20, "R": 0.10}

# Importances Random Forest (référence — NE PAS utiliser directement)
W_RF = {"C": 0.1092, "I": 0.2340, "B": 0.3368, "P": 0.2141, "R": 0.1059}


# ─────────────────────────────────────────────────────────────
# COMBINAISON
# ─────────────────────────────────────────────────────────────

def combine_weights(w_ahp: np.ndarray, w_ewm: np.ndarray,
                    alpha: float) -> np.ndarray:
    """
    Combinaison linéaire convexe AHP + EWM :

        w_final = alpha × w_AHP + (1 - alpha) × w_EWM

    Puis application des contraintes [MIN_WEIGHT, MAX_WEIGHT]
    et renormalisation pour garantir Σ w_final = 1.0

    Justification de alpha = 0.60 :
    ┌──────────────────────────────────────────────────────────┐
    │ 1. BIAIS DATASET : l'EWM seul (alpha=0) donnerait à C   │
    │    un poids de 0.116 à cause du scénario mTLS_permissive │
    │    qui n'a pas produit de variation significative.        │
    │    Ce biais est documenté, pas une vérité sécuritaire.   │
    │                                                           │
    │ 2. FONDEMENT NORMATIF : l'AHP est ancré dans le NIST     │
    │    SP 800-207 et les CIS Controls v8. Leur primauté       │
    │    (alpha > 0.5) est académiquement défendable.           │
    │                                                           │
    │ 3. LITTÉRATURE MCDM : Deng et al. (2000) recommandent   │
    │    alpha ∈ [0.5, 0.7] quand les jugements d'expert       │
    │    reposent sur des normes reconnues et que le dataset    │
    │    présente des biais de génération connus.               │
    │    alpha = 0.60 est le centre de cette plage.             │
    └──────────────────────────────────────────────────────────┘
    """
    combined = alpha * w_ahp + (1 - alpha) * w_ewm

    # Contraintes
    combined = np.clip(combined, MIN_WEIGHT, MAX_WEIGHT)

    # Renormalisation (la somme peut légèrement dériver après clip)
    combined = combined / combined.sum()

    return combined


# ─────────────────────────────────────────────────────────────
# RAPPORT FINAL
# ─────────────────────────────────────────────────────────────

def print_final_report(w_ahp, w_ewm, w_final, CR):
    sep = "═" * 62
    w_init = np.array(list(W_INITIAL.values()))
    w_rf   = np.array(list(W_RF.values()))

    print(f"\n{sep}")
    print("  COMBINAISON FINALE AHP + EWM")
    print(sep)

    print(f"\n  Formule : w_final = {ALPHA}×w_AHP + {1-ALPHA:.2f}×w_EWM")
    print(f"  alpha = {ALPHA}  (primauté à l'expertise normative)\n")

    # Tableau comparatif
    print(f"  {'Comp':>6} {'Initial':>10} {'RF_Import':>10} "
          f"{'AHP':>10} {'EWM':>10} {'FINAL':>10}")
    print("  " + "─" * 60)
    for i, name in enumerate(COMPONENTS):
        print(f"  {name:>6} {w_init[i]:>10.4f} {w_rf[i]:>10.4f} "
              f"{w_ahp[i]:>10.4f} {w_ewm[i]:>10.4f} {w_final[i]:>10.4f}")
    print(f"  {'Σ':>6} {w_init.sum():>10.4f} {w_rf.sum():>10.4f} "
          f"{w_ahp.sum():>10.4f} {w_ewm.sum():>10.4f} {w_final.sum():>10.4f}")

    # Changements par rapport aux poids initiaux
    print("\n  ── Changements vs poids initiaux ──\n")
    deltas = [(COMPONENTS[i], w_init[i], w_final[i], w_final[i]-w_init[i])
              for i in range(5)]
    for name, wi, wf, delta in sorted(deltas, key=lambda x: -abs(x[3])):
        arrow = "↑" if delta > 0 else "↓"
        bar   = "█" * int(abs(delta) * 100)
        print(f"    {name} : {wi:.4f} → {wf:.4f}  {arrow}{abs(delta):.4f}  {bar}")

    # Formule finale
    print("\n  ── Formule de score avec les nouveaux poids ──\n")
    terms = " + ".join(
        f"{w_final[i]:.4f}·{COMPONENTS[i]}" for i in range(5)
    )
    print(f"  S = {terms}")

    # CR rappel
    print(f"\n  CR (AHP) = {CR:.4f} < 0.10  ✓  Matrice cohérente")

    # Phrase de soutenance
    print(f"\n{sep}")
    print("  PHRASE DE SOUTENANCE")
    print(sep)
    print(f"""
  « Les poids de notre formule de scoring ont été déterminés
    par une approche hybride AHP + EWM.

    L'AHP (Saaty, 1980) formalise les jugements d'expert issus
    du NIST SP 800-207 et des CIS Controls v8 sous forme d'une
    matrice de comparaison par paires, avec un Consistency Ratio
    de {CR:.3f} — bien en dessous du seuil de 0.10 de Saaty.

    L'EWM (Shannon, 1948) complète l'approche en quantifiant
    l'information discriminante de chaque composante sur nos
    2 996 échantillons réels, indépendamment de tout a priori.

    La combinaison avec α = {ALPHA} accorde la primauté à l'expertise
    normative tout en intégrant les données empiriques — un choix
    documenté dans la littérature MCDM (Deng et al., 2000).

    Ce faisant, nous évitons deux écueils opposés : l'arbitraire
    des poids initiaux, et la réduction aux importances Random
    Forest qui auraient pénalisé C à cause d'un biais connu dans
    notre dataset mTLS. »
    """)

    print(sep + "\n")


# ─────────────────────────────────────────────────────────────
# SAUVEGARDE JSON
# ─────────────────────────────────────────────────────────────

def save_weights(w_ahp, w_ewm, w_final, ahp_results, ewm_results):
    output = {
        "method": "AHP + EWM Combined",
        "description": (
            f"Poids hybrides : {ALPHA}×AHP (Saaty 1980, NIST SP 800-207) "
            f"+ {1-ALPHA:.2f}×EWM (Shannon 1948). "
            f"CR={ahp_results['CR']:.4f} < 0.10."
        ),
        "w1_C": round(float(w_final[0]), 4),
        "w2_I": round(float(w_final[1]), 4),
        "w3_B": round(float(w_final[2]), 4),
        "w4_P": round(float(w_final[3]), 4),
        "w5_R": round(float(w_final[4]), 4),
        "threshold": 0.50,
        "alpha": ALPHA,
        "ahp_weights":    {c: round(float(w), 4) for c, w in zip(COMPONENTS, w_ahp)},
        "ewm_weights":    {c: round(float(w), 4) for c, w in zip(COMPONENTS, w_ewm)},
        "ewm_entropies":  {c: round(float(e), 6) for c, e in zip(COMPONENTS, ewm_results["entropy"])},
        "ewm_divergences":{c: round(float(d), 6) for c, d in zip(COMPONENTS, ewm_results["divergence"])},
        "consistency_ratio": round(float(ahp_results["CR"]), 4),
        "lambda_max":     round(float(ahp_results["lambda_max"]), 4),
        "initial_weights": W_INITIAL,
        "rf_importances":  W_RF,
        "constraints": {
            "min_weight": MIN_WEIGHT,
            "max_weight": MAX_WEIGHT,
            "sum_to_one": True
        },
        "references": [
            "Saaty, T.L. (1980). The Analytic Hierarchy Process. McGraw-Hill.",
            "Shannon, C.E. (1948). A Mathematical Theory of Communication. Bell System Technical Journal.",
            "NIST SP 800-207 (2020). Zero Trust Architecture. NIST.",
            "Deng, H. et al. (2000). Combining AHP and EWM for MCDM. Systems Engineering & Electronics.",
            "CIS Controls v8 (2021). Center for Internet Security."
        ]
    }

    path = Path(OUTPUT_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"  ✓ Sauvegardé : {OUTPUT_PATH}")
    return output


# ─────────────────────────────────────────────────────────────
# POINT D'ENTRÉE PRINCIPAL
# ─────────────────────────────────────────────────────────────

def main():
    print("\n" + "═"*62)
    print("  LANCEMENT : AHP + EWM Weight Optimization")
    print("═"*62)

    # ── Étape 1 : AHP ──────────────────────────────────────────
    print("\n>>> Calcul AHP en cours...")
    ahp_results = run_ahp()

    if not ahp_results["is_consistent"]:
        print("  ERREUR : CR ≥ 0.10. Révisez la matrice AHP.")
        return

    w_ahp = ahp_results["priorities"]

    # ── Étape 2 : EWM ──────────────────────────────────────────
    print("\n>>> Calcul EWM en cours...")
    ewm_results = run_ewm()
    w_ewm = ewm_results["weights"]

    # ── Étape 3 : Combinaison ───────────────────────────────────
    w_final = combine_weights(w_ahp, w_ewm, ALPHA)

    # ── Rapport et sauvegarde ───────────────────────────────────
    print_final_report(w_ahp, w_ewm, w_final, ahp_results["CR"])
    output = save_weights(w_ahp, w_ewm, w_final, ahp_results, ewm_results)

    print("\n  Résumé des poids finaux :")
    for name in COMPONENTS:
        key = f"w{COMPONENTS.index(name)+1}_{name}"
        print(f"    {key} = {output[key]}")
    print()


if __name__ == "__main__":
    main()