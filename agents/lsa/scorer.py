# agents/lsa/scorer.py
# Calcul du score de sécurité S = w1·C + w2·I + w3·B + w4·P + w5·R

import logging
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Chargement des poids depuis weights_optimal.json
# ─────────────────────────────────────────────────────────────
 
def _load_weights() -> dict:
    """
    Charge les poids optimisés AHP+EWM depuis weights_optimal.json.
    Le fichier doit se trouver dans le même dossier que scorer.py.
 
    Si le fichier est absent ou corrompu, on utilise les poids
    initiaux en fallback et on log un avertissement.
    """
    weights_path = Path(__file__).parent / "weights_optimal.json"
 
    # Poids initiaux utilisés en cas d'échec du chargement
    fallback = {
        'w1': 0.25,  # C
        'w2': 0.20,  # I
        'w3': 0.25,  # B
        'w4': 0.20,  # P
        'w5': 0.10,  # R
    }
 
    if not weights_path.exists():
        logger.warning(
            f"weights_optimal.json introuvable dans {weights_path.parent}. "
            f"Poids initiaux utilisés en fallback. "
            f"Lancez weight_optimization/combine_weights.py pour générer le fichier."
        )
        return fallback
 
    try:
        with open(weights_path, encoding="utf-8") as f:
            data = json.load(f)
 
        weights = {
            'w1': data["w1_C"],
            'w2': data["w2_I"],
            'w3': data["w3_B"],
            'w4': data["w4_P"],
            'w5': data["w5_R"],
        }
 
        # Vérification que la somme est bien ≈ 1.0
        total = sum(weights.values())
        if not (0.99 <= total <= 1.01):
            raise ValueError(f"Somme des poids = {total:.4f} ≠ 1.0")
 
        logger.info(
            f"Poids AHP+EWM chargés depuis {weights_path.name} : "
            f"C={weights['w1']} I={weights['w2']} B={weights['w3']} "
            f"P={weights['w4']} R={weights['w5']} "
            f"(méthode: {data.get('method', 'N/A')}, "
            f"CR={data.get('consistency_ratio', 'N/A')})"
        )
        return weights
 
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        logger.warning(
            f"Erreur lors du chargement de weights_optimal.json : {e}. "
            f"Poids initiaux utilisés en fallback."
        )
        return fallback
 
 
# ─────────────────────────────────────────────────────────────
# Dataclass du score
# ─────────────────────────────────────────────────────────────
@dataclass
class SecurityScore:
    service_name: str
    C: float       # Confidentialité (mTLS)
    I: float       # Intégrité (OPA violations)
    B: float       # Comportement (Falco alerts)
    P: float       # Policy compliance (OPA)
    R: float       # Reliability (error rate)
    total: float
    status: str
    timestamp: str
    weights_source: str

class SecurityScorer:

    # Poids de la formule — somme = 1.0
    WEIGHTS = _load_weights()

    # Seuils de statut
    THRESHOLD_ISOLATED  = 0.30
    THRESHOLD_CRITICAL  = 0.50
    THRESHOLD_WARNING   = 0.70
    THRESHOLD_HEALTHY   = 0.85

    def __init__(self, service_name: str):
        self.service_name = service_name

    def compute(self, components: dict) -> SecurityScore:
        C = components.get('C', 0.5)
        I = components.get('I', 0.5)
        B = components.get('B', 0.5)
        P = components.get('P', 0.5)
        R = components.get('R', 0.5)

        w = self.WEIGHTS
        total = (
            w['w1'] * C +
            w['w2'] * I +
            w['w3'] * B +
            w['w4'] * P +
            w['w5'] * R
        )
        total = round(min(1.0, max(0.0, total)), 4)

        # Déterminer le statut
        if total < self.THRESHOLD_ISOLATED:
            status = 'ISOLATED'
        elif total < self.THRESHOLD_CRITICAL:
            status = 'CRITICAL'
        elif total < self.THRESHOLD_WARNING:
            status = 'WARNING'
        elif total < self.THRESHOLD_HEALTHY:
            status = 'DEGRADED'
        else:
            status = 'HEALTHY'

        weights_path = Path(__file__).parent / "weights_optimal.json"
        weights_source = "AHP+EWM" if weights_path.exists() else "fallback"

        score = SecurityScore(
            service_name = self.service_name,
            C     = round(C, 4),
            I     = round(I, 4),
            B     = round(B, 4),
            P     = round(P, 4),
            R     = round(R, 4),
            total = total,
            status= status,
            timestamp = datetime.utcnow().isoformat(),
            weights_source = weights_source,
        )

        logger.info(
            f'Score {self.service_name}: {total:.4f} [{status}] '
            f'C={C:.2f} I={I:.2f} B={B:.2f} P={P:.2f} R={R:.2f} '
            f"(poids: {weights_source})"
        )
        return score

    def get_weights_info(self) -> dict:
        """
        Retourne les poids actuellement utilisés — utile pour le debug
        et pour l'affichage dans Grafana/logs.
        """
        weights_path = Path(__file__).parent / "weights_optimal.json"
        if weights_path.exists():
            with open(weights_path, encoding="utf-8") as f:
                data = json.load(f)
            return {
                "method":             data.get("method", "N/A"),
                "consistency_ratio":  data.get("consistency_ratio", "N/A"),
                "alpha":              data.get("alpha", "N/A"),
                "w1_C":               self.WEIGHTS['w1'],
                "w2_I":               self.WEIGHTS['w2'],
                "w3_B":               self.WEIGHTS['w3'],
                "w4_P":               self.WEIGHTS['w4'],
                "w5_R":               self.WEIGHTS['w5'],
            }
        return {"method": "fallback", **self.WEIGHTS}