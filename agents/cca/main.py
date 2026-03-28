from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from prometheus_client import Gauge, make_asgi_app
import logging
import uvicorn
import httpx
import json

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s [CCA] %(levelname)s: %(message)s')
logger = logging.getLogger('cca')

app = FastAPI(title='Central Composition Agent', version='2.1.0')

class ScoreReport(BaseModel):
    service: str
    score: float
    components: Dict[str, float]
    status: str
    timestamp: str

class WorkflowComposition(BaseModel):
    workflow: str
    selected: List[dict]
    excluded: List[dict]
    composition_time: str
    all_healthy: bool

scores_table: Dict[str, ScoreReport] = {}
isolated_services: set = set()

# Compteur de scores consécutifs bons avant de lever l'isolation
recovery_counter: Dict[str, int] = {}
RECOVERY_THRESHOLD = 3  # 3 scores consécutifs > seuil pour lever l'isolation

WORKFLOWS = {
    'checkout': ['service-auth', 'service-orders', 'service-payment', 'service-notification'],
    'login': ['service-auth'],
    'orders': ['service-auth', 'service-orders'],
}

ISOLATION_THRESHOLD = 0.5
SCORE_TTL = timedelta(minutes=3)
KUBERNETES_API = 'https://kubernetes.default.svc.cluster.local'
NAMESPACE = 'app'

CCA_SCORE_GAUGE = Gauge(
    'cca_service_score',
    'Score agrégé par service selon le CCA',
    ['service', 'status']
)

async def get_k8s_token():
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as f:
        return f.read().strip()

async def apply_isolation_policy(service_name: str):
    """Applique une AuthorizationPolicy DENY sur le service via l'API Kubernetes"""
    token = await get_k8s_token()
    policy = {
        "apiVersion": "security.istio.io/v1beta1",
        "kind": "AuthorizationPolicy",
        "metadata": {
            "name": f"isolate-{service_name}",
            "namespace": NAMESPACE
        },
        "spec": {
            "selector": {
                "matchLabels": {"app": service_name}
            },
            "action": "DENY",
            "rules": [{
                "from": [{
                    "source": {
                        "namespaces": ["app"]
                    }
                }]
            }] # DENY le trafic venant du namespace app des microservices
        }
    }

    async with httpx.AsyncClient(verify=False) as client:
        # Vérifier si la policy existe déjà
        check = await client.get(
            f"{KUBERNETES_API}/apis/security.istio.io/v1beta1/namespaces/{NAMESPACE}/authorizationpolicies/isolate-{service_name}",
            headers={"Authorization": f"Bearer {token}"}
        )

        if check.status_code == 404:
            # Créer la policy
            resp = await client.post(
                f"{KUBERNETES_API}/apis/security.istio.io/v1beta1/namespaces/{NAMESPACE}/authorizationpolicies",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                content=json.dumps(policy)
            )
            if resp.status_code in [200, 201]:
                logger.warning(f"🚨 ISOLATION RÉSEAU ACTIVE : {service_name} bloqué par AuthorizationPolicy")
                isolated_services.add(service_name)
            else:
                logger.error(f"Erreur création policy : {resp.status_code} {resp.text}")
        else:
            logger.info(f"Policy d'isolation déjà active pour {service_name}")
            isolated_services.add(service_name)

async def remove_isolation_policy(service_name: str):
    """Supprime l'AuthorizationPolicy d'isolation"""
    token = await get_k8s_token()

    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.delete(
            f"{KUBERNETES_API}/apis/security.istio.io/v1beta1/namespaces/{NAMESPACE}/authorizationpolicies/isolate-{service_name}",
            headers={"Authorization": f"Bearer {token}"}
        )
        if resp.status_code in [200, 404]:
            logger.info(f"✅ ISOLATION LEVÉE : {service_name} de retour en ligne")
            isolated_services.discard(service_name)
            recovery_counter[service_name] = 0
        else:
            logger.error(f"Erreur suppression policy : {resp.status_code} {resp.text}")

@app.get('/health')
def health():
    return {'status': 'healthy', 'service': 'CCA', 'version': '2.1.0', 'services_tracked': len(scores_table), 'isolated_services': list(isolated_services)}

@app.post('/api/scores')
async def receive_score(report: ScoreReport):
    scores_table[report.service] = report
    CCA_SCORE_GAUGE.labels(service=report.service, status=report.status).set(report.score)
    if report.score < ISOLATION_THRESHOLD:
        logger.warning(f"Score critique : {report.service} = {report.score:.4f}")
        await apply_isolation_policy(report.service)
    elif report.service in isolated_services:
        # Service isolé mais score remonté — incrémenter le compteur
        recovery_counter[report.service] = recovery_counter.get(report.service, 0) + 1
        count = recovery_counter[report.service]
        logger.info(f"Récupération {report.service} : {count}/{RECOVERY_THRESHOLD} scores bons")
        if count >= RECOVERY_THRESHOLD:
            # Assez de scores consécutifs bons → lever l'isolation
            await remove_isolation_policy(report.service)
            logger.info(f"✅ {report.service} récupéré après {count} scores consécutifs bons")
    else:
        # Service sain normal
        recovery_counter[report.service] = 0
    return {'received': True, 'service': report.service, 'isolated': report.service in isolated_services, 'recovery_count': recovery_counter.get(report.service, 0)}


@app.get('/api/compose', response_model=WorkflowComposition)
def compose_workflow(workflow: str):
    if workflow not in WORKFLOWS:
        raise HTTPException(status_code=404, detail=f'Workflow {workflow} inconnu')
    required_services = WORKFLOWS[workflow]
    selected = []
    excluded = []
    now = datetime.utcnow()
    for service in required_services:
        report = scores_table.get(service)
        if report is None:
            excluded.append({'service': service, 'reason': 'Pas encore évalué par un LSA', 'score': None})
            continue
        report_time = datetime.fromisoformat(report.timestamp)
        if now - report_time > SCORE_TTL:
            excluded.append({'service': service, 'reason': f'Score expiré', 'score': report.score})
            continue
        if service in isolated_services:
            count= recovery_counter.get(service, 0)
            excluded.append({
                'service': service,
                'reason': f' Isolé réseau - AuthorizationPolicy DENY active (récupération: {count}/{RECOVERY_THRESHOLD})',
                'score': report.score,
                'status': report.status
            })
        elif report.score >= ISOLATION_THRESHOLD :
            selected.append({'service': service, 'score': report.score, 'status': report.status, 'components': report.components})
        else:
            reason = f'Score trop bas ({report.score:.4f} < {ISOLATION_THRESHOLD})'
            excluded.append({'service': service, 'reason': reason,
                           'score': report.score, 'status': report.status})
    selected.sort(key=lambda x: x['score'], reverse=True)
    result = WorkflowComposition(
        workflow=workflow,
        selected=selected,
        excluded=excluded,
        composition_time=now.isoformat(),
        all_healthy=len(excluded) == 0
    )
    logger.info(f'Composition {workflow}: {len(selected)} sélectionnés, {len(excluded)} exclus')
    return result

@app.get('/api/status')
def get_status():
    now = datetime.utcnow()
    status_list = []
    for service, report in scores_table.items():
        age = (now - datetime.fromisoformat(report.timestamp)).seconds
        status_list.append({
            'service': service,
            'score': report.score,
            'status': report.status,
            'components': report.components,
            'last_update_seconds': age,
            'isolated': service in isolated_services,
            'recovery_count': recovery_counter.get(service, 0),
            'recovery_needed': RECOVERY_THRESHOLD
        })
    status_list.sort(key=lambda x: x['score'], reverse=True)
    return {'services': status_list, 'isolation_threshold': ISOLATION_THRESHOLD, 'isolated_services': list(isolated_services)}

metrics_app = make_asgi_app()
app.mount('/metrics', metrics_app)

if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8080)