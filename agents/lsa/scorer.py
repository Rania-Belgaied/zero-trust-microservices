# agents/lsa/scorer.py
# Calcul du score de sécurité S = w1·C + w2·I + w3·B + w4·P + w5·R

import logging
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

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

class SecurityScorer:

    # Poids de la formule — somme = 1.0
    WEIGHTS = {
        'w1': 0.25,  # C : confidentialité
        'w2': 0.20,  # I : intégrité
        'w3': 0.25,  # B : comportement
        'w4': 0.20,  # P : policy
        'w5': 0.10,  # R : reliability
    }

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

        score = SecurityScore(
            service_name = self.service_name,
            C     = round(C, 4),
            I     = round(I, 4),
            B     = round(B, 4),
            P     = round(P, 4),
            R     = round(R, 4),
            total = total,
            status= status,
            timestamp = datetime.utcnow().isoformat()
        )

        logger.info(
            f'Score {self.service_name}: {total:.4f} [{status}] '
            f'C={C:.2f} I={I:.2f} B={B:.2f} P={P:.2f} R={R:.2f}'
        )
        return score