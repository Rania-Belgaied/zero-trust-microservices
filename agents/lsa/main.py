# agents/lsa/main.py
# Agent de Sécurité Local — point d'entrée principal

import asyncio
import logging
import os
import httpx
from prometheus_client import Gauge, Counter, start_http_server
from collectors import DataCollector
from scorer import SecurityScorer
from dataset_logger import init_dataset, log_sample

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [LSA-%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger('main')

# Configuration
TARGET_SERVICE   = os.getenv('TARGET_SERVICE', 'service-payment')
CCA_URL          = os.getenv('CCA_URL', 'http://cca.agents.svc.cluster.local:8080')
COLLECT_INTERVAL = int(os.getenv('COLLECT_INTERVAL', '30'))
METRICS_PORT     = int(os.getenv('METRICS_PORT', '9090'))

# parser service et contexte
if ':' in TARGET_SERVICE:
    _SERVICE_NAME, _CONTEXT = TARGET_SERVICE.split(':', 1)
else:
    _SERVICE_NAME = TARGET_SERVICE
    _CONTEXT = 'ctx-a'

# ── Métriques Prometheus ──────────────────────────────────────
SCORE_GAUGE = Gauge(
    'security_score',
    'Score de sécurité par composante',
    ['service', 'component']
)

SCORE_TOTAL = Gauge(
    'security_score_total',
    'Score de sécurité total',
    ['service', 'status']
)

COLLECT_ERRORS = Counter(
    'lsa_collect_errors_total',
    'Nombre d erreurs de collecte',
    ['service']
)

COLLECT_RUNS = Counter(
    'lsa_collect_runs_total',
    'Nombre de cycles de collecte',
    ['service']
)

# ── Boucle principale ─────────────────────────────────────────
async def run_collection_loop(
    collector: DataCollector,
    scorer: SecurityScorer
):
    while True:
        try:
            logger.info(f'=== Collecte pour {TARGET_SERVICE} ===')

            # 1. Collecter toutes les composantes en parallèle
            components = await collector.collect_all()
            logger.info(f'Composantes: {components}')

            # 2. Calculer le score
            score = scorer.compute(components)

            # 3. Mettre à jour les métriques Prometheus
            for component, value in components.items():
                SCORE_GAUGE.labels(
                    service=TARGET_SERVICE,
                    component=component
                ).set(value)

            # Reset les anciens statuts
            for status in ['HEALTHY','DEGRADED','WARNING','CRITICAL','ISOLATED']:
                SCORE_TOTAL.labels(
                    service=TARGET_SERVICE,
                    status=status
                ).set(0)

            SCORE_TOTAL.labels(
                service=TARGET_SERVICE,
                status=score.status
            ).set(score.total)

            COLLECT_RUNS.labels(service=TARGET_SERVICE).inc()

            # 4. Logger pour le dataset
            log_sample(TARGET_SERVICE, components, score.total, score.status)

            # 5. Envoyer le score au CCA
            await send_score_to_cca(score)

            logger.info(
                f'Score final {TARGET_SERVICE}: '
                f'{score.total:.4f} [{score.status}]'
            )

        except Exception as e:
            logger.error(f'Erreur dans la boucle de collecte: {e}')
            COLLECT_ERRORS.labels(service=TARGET_SERVICE).inc()

        await asyncio.sleep(COLLECT_INTERVAL)

async def send_score_to_cca(score):
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            payload = {
                'service':    TARGET_SERVICE,  # ex: "service-payment:ctx-a"
                'score':      score.total,
                'components': {
                    'C': score.C,
                    'I': score.I,
                    'B': score.B,
                    'P': score.P,
                    'R': score.R
                },
                'status':    score.status,
                'timestamp': score.timestamp
            }
            resp = await client.post(
                f'{CCA_URL}/api/scores',
                json=payload
            )
            if resp.status_code == 200:
                logger.info('Score envoyé au CCA avec succès')
            else:
                logger.warning(f'CCA a répondu {resp.status_code}')
    except Exception as e:
        logger.warning(f'CCA non disponible: {e}')

async def main():
    # Démarrer le serveur Prometheus
    logger.info(f'Démarrage métriques Prometheus sur port {METRICS_PORT}')
    start_http_server(METRICS_PORT)

    # Initialiser les composants
    collector = DataCollector()
    scorer    = SecurityScorer(service_name=TARGET_SERVICE)

    logger.info(f'LSA démarré pour {TARGET_SERVICE}')
    init_dataset()
    logger.info(f'Intervalle de collecte: {COLLECT_INTERVAL}s')
    logger.info(f'CCA URL: {CCA_URL}')

    try:
        await run_collection_loop(collector, scorer)
    finally:
        await collector.close()

if __name__ == '__main__':
    asyncio.run(main())