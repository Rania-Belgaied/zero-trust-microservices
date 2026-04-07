# agents/lsa/dataset_logger.py
# Module de logging pour générer le dataset ML

import csv
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

DATASET_PATH = os.getenv('DATASET_PATH', '/data/security_dataset.csv')
ATTACK_TYPE  = os.getenv('ATTACK_TYPE', 'none')  # injecté lors des tests

def init_dataset():
    """Créer le fichier CSV avec les headers si inexistant"""
    os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
    if not os.path.exists(DATASET_PATH):
        with open(DATASET_PATH, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp', 'service',
                'C', 'I', 'B', 'P', 'R',
                'score', 'status',
                'attack_type', 'label'
            ])
        logger.info(f"Dataset initialisé : {DATASET_PATH}")

def log_sample(service_name: str, components: dict,
               score: float, status: str):
    """
    Enregistrer un échantillon dans le dataset.
    Le label est déduit automatiquement de ATTACK_TYPE.
    """
    attack_type = ATTACK_TYPE
    # label=1 si sous attaque, 0 si état sain
    label = 0 if attack_type == 'none' else 1

    row = [
        datetime.utcnow().isoformat(),
        service_name,
        round(components['C'], 4),
        round(components['I'], 4),
        round(components['B'], 4),
        round(components['P'], 4),
        round(components['R'], 4),
        round(score, 4),
        status,
        attack_type,
        label
    ]

    with open(DATASET_PATH, 'a', newline='') as f:
        csv.writer(f).writerow(row)

    logger.debug(f"Sample loggé : {service_name} | score={score:.4f} | label={label} | attack={attack_type}")
