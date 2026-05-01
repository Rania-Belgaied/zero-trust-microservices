from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from prometheus_client import Gauge, make_asgi_app
import logging
import uvicorn
import httpx
import json
import ssl
import urllib.request
import asyncio

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s [CCA] %(levelname)s: %(message)s')
logger = logging.getLogger('cca')

app = FastAPI(title='Central Composition Agent', version='3.1.0')

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

recovery_counter: Dict[str, int] = {}
RECOVERY_THRESHOLD = 3

# contexte actif par service et historique des basculements
active_routing: Dict[str, str] = {}
routing_history: List[dict] = []

# seuil de score pour réintégration (plus strict que le seuil d'isolation)
RECOVERY_THRESHOLD_SCORE = 0.65

# liste des contextes disponibles par service
SERVICE_CONTEXTS = {
    'service-auth':         ['ctx-a', 'ctx-b'],
    'service-orders':       ['ctx-a', 'ctx-b'],
    'service-payment':      ['ctx-a', 'ctx-b'],
    'service-notification': ['ctx-a', 'ctx-b'],
}

WORKFLOWS = {
    'checkout': ['service-auth', 'service-orders', 'service-payment', 'service-notification'],
    'login': ['service-auth'],
    'orders': ['service-auth', 'service-orders'],
}

ISOLATION_THRESHOLD = 0.5
SCORE_TTL = timedelta(minutes=3)
KUBERNETES_API = 'https://kubernetes.default.svc.cluster.local'
NAMESPACE = 'app'

# ajout du label 'context' dans la Gauge
CCA_SCORE_GAUGE = Gauge(
    'cca_service_score',
    'Score agrégé par service et contexte',
    ['service', 'context', 'status']
)

# métrique Prometheus pour suivre le contexte actif dans Grafana
CCA_ACTIVE_CONTEXT = Gauge(
    'cca_active_context',
    'Contexte actif par service (0=ctx-a, 1=ctx-b)',
    ['service']
)

async def get_k8s_token():
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as f:
        return f.read().strip()

# isole uniquement l'instance spécifique (service + context), pas tout le service
async def apply_isolation_policy(service_name: str, context: str):
    token = await get_k8s_token()
    instance_name = f"{service_name}-{context}"  # ex: service-payment-ctx-a
    policy = {
        "apiVersion": "security.istio.io/v1beta1",
        "kind": "AuthorizationPolicy",
        "metadata": {
            "name": f"isolate-{instance_name}",
            "namespace": NAMESPACE
        },
        "spec": {
            "selector": {
                "matchLabels": {
                    "app": service_name,
                    "context": context        # cible uniquement ce contexte
                }
            },
            "action": "DENY",
            "rules": [{
                "from": [{
                    "source": {
                        "namespaces": ["app"]
                    }
                }]
            }]
        }
    }

    async with httpx.AsyncClient(verify=False) as client:
        check = await client.get(
            f"{KUBERNETES_API}/apis/security.istio.io/v1beta1/namespaces/{NAMESPACE}/authorizationpolicies/isolate-{instance_name}",
            headers={"Authorization": f"Bearer {token}"}
        )
        if check.status_code == 404:
            resp = await client.post(
                f"{KUBERNETES_API}/apis/security.istio.io/v1beta1/namespaces/{NAMESPACE}/authorizationpolicies",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                content=json.dumps(policy)
            )
            if resp.status_code in [200, 201]:
                logger.warning(f"🚨 ISOLATION ACTIVE : {instance_name} bloqué par AuthorizationPolicy")
                isolated_services.add(instance_name)  # clé = service-context
            else:
                logger.error(f"Erreur création policy : {resp.status_code} {resp.text}")
        else:
            logger.info(f"Policy d'isolation déjà active pour {instance_name}")
            isolated_services.add(instance_name)

# supprime l'isolation de l'instance spécifique
async def remove_isolation_policy(service_name: str, context: str):
    token = await get_k8s_token()
    instance_name = f"{service_name}-{context}"

    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.delete(
            f"{KUBERNETES_API}/apis/security.istio.io/v1beta1/namespaces/{NAMESPACE}/authorizationpolicies/isolate-{instance_name}",
            headers={"Authorization": f"Bearer {token}"}
        )
        if resp.status_code in [200, 404]:
            logger.info(f"✅ ISOLATION LEVÉE : {instance_name} de retour en ligne")
            isolated_services.discard(instance_name)
            recovery_counter[instance_name] = 0
        else:
            logger.error(f"Erreur suppression policy : {resp.status_code} {resp.text}")

# patch du selector du Service k8s pour basculer le trafic vers target_context
async def reroute_service(service_name: str, target_context: str):
    token = await get_k8s_token()
    previous_context = active_routing.get(service_name, 'ctx-a')

    patch_body = json.dumps({
        "spec": {
            "selector": {
                "app": service_name,
                "context": target_context
            }
        }}).encode()
        

    
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        f"{KUBERNETES_API}/api/v1/namespaces/{NAMESPACE}/services/{service_name}",
        data=patch_body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/merge-patch+json"
        },
        method='PATCH'
    )
    try:
        resp = urllib.request.urlopen(req, context=ssl_ctx)
        if resp.status in [200, 201]:
            active_routing[service_name] = target_context
            routing_history.append({
                "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S'),
                "service": service_name,
                "from_context": previous_context,
                "to_context": target_context,
            })
            ctx_value = 0 if target_context == "ctx-a" else 1
            CCA_ACTIVE_CONTEXT.labels(service=service_name).set(ctx_value)
            logger.warning(
                f"🔀 BASCULEMENT : {service_name} {previous_context} → {target_context}"
            )
    except Exception as e:
        logger.error(f"Erreur patch Service {service_name}: {e}")


#===============================================
async def spawn_recovery_instance(service_name: str) -> str:
    """
    Cree un Deployment applicatif + un Deployment LSA pour le service compromis.
    Appele uniquement quand tous les contextes existants sont isoles.
    Retourne le nom du nouveau contexte, ou None si echec.
    """
    token = await get_k8s_token()
    recovery_ctx = "ctx-recovery"

    ssl_c = ssl.create_default_context()
    ssl_c.check_hostname = False
    ssl_c.verify_mode = ssl.CERT_NONE

    # ── 1. Lire le Deployment ctx-a comme template ────────────────────────
    try:
        get_req = urllib.request.Request(
            f"{KUBERNETES_API}/apis/apps/v1/namespaces/{NAMESPACE}"
            f"/deployments/{service_name}-ctx-a",
            headers={"Authorization": f"Bearer {token}"},
            method='GET'
        )
        template = json.loads(
            urllib.request.urlopen(get_req, context=ssl_c).read().decode()
        )
    except Exception as e:
        logger.error(f"Impossible de lire le template pour {service_name}: {e}")
        return None

    # ── 2. Creer le Deployment applicatif ctx-recovery ────────────────────
    app_deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": f"{service_name}-{recovery_ctx}",
            "namespace": NAMESPACE,
            "labels": {
                "app": service_name,
                "context": recovery_ctx,
                "managed-by": "cca-recovery"
            }
        },
        "spec": {
            "replicas": 1,
            "selector": {
                "matchLabels": {
                    "app": service_name,
                    "context": recovery_ctx
                }
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app": service_name,
                        "context": recovery_ctx
                    }
                },
                "spec": template["spec"]["template"]["spec"]
            }
        }
    }

    try:
        create_req = urllib.request.Request(
            f"{KUBERNETES_API}/apis/apps/v1/namespaces/{NAMESPACE}/deployments",
            data=json.dumps(app_deployment).encode(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            method='POST'
        )
        urllib.request.urlopen(create_req, context=ssl_c)
        logger.warning(
            f"RECOVERY APP cree : {service_name}-{recovery_ctx}"
        )
    except Exception as e:
        logger.error(f"Erreur creation Deployment app {service_name}: {e}")
        return None

    # ── 3. Lire le Deployment LSA ctx-a comme template ────────────────────
    try:
        lsa_name_template = f"lsa-{service_name}-ctx-a"
        get_lsa_req = urllib.request.Request(
            f"{KUBERNETES_API}/apis/apps/v1/namespaces/agents"
            f"/deployments/{lsa_name_template}",
            headers={"Authorization": f"Bearer {token}"},
            method='GET'
        )
        lsa_template = json.loads(
            urllib.request.urlopen(get_lsa_req, context=ssl_c).read().decode()
        )
    except Exception as e:
        logger.error(f"Impossible de lire le template LSA pour {service_name}: {e}")
        # App deployee mais pas le LSA — on retourne quand meme le contexte
        # Le CCA monitore sans LSA jusqu'a correction manuelle
        if service_name in SERVICE_CONTEXTS:
            if recovery_ctx not in SERVICE_CONTEXTS[service_name]:
                SERVICE_CONTEXTS[service_name].append(recovery_ctx)
        return recovery_ctx

    # ── 4. Modifier la variable TARGET_SERVICE dans le template LSA ───────
    lsa_spec = lsa_template["spec"]["template"]["spec"]
    for container in lsa_spec["containers"]:
        for env_var in container.get("env", []):
            if env_var["name"] == "TARGET_SERVICE":
                env_var["value"] = f"{service_name}:{recovery_ctx}"
                break

    # ── 5. Creer le Deployment LSA ctx-recovery ───────────────────────────
    lsa_deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": f"lsa-{service_name}-{recovery_ctx}",
            "namespace": "agents",
            "labels": {
                "app": f"lsa-{service_name}-{recovery_ctx}",
                "managed-by": "cca-recovery"
            }
        },
        "spec": {
            "replicas": 1,
            "selector": {
                "matchLabels": {
                    "app": f"lsa-{service_name}-{recovery_ctx}"
                }
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app": f"lsa-{service_name}-{recovery_ctx}"
                    }
                },
                "spec": lsa_spec
            }
        }
    }

    try:
        create_lsa_req = urllib.request.Request(
            f"{KUBERNETES_API}/apis/apps/v1/namespaces/agents/deployments",
            data=json.dumps(lsa_deployment).encode(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            method='POST'
        )
        urllib.request.urlopen(create_lsa_req, context=ssl_c)
        logger.warning(
            f"RECOVERY LSA cree : lsa-{service_name}-{recovery_ctx}"
        )
    except Exception as e:
        logger.error(f"Erreur creation LSA {service_name}: {e}")

    # ── 6. Enregistrer le nouveau contexte dans SERVICE_CONTEXTS ──────────
    if service_name in SERVICE_CONTEXTS:
        if recovery_ctx not in SERVICE_CONTEXTS[service_name]:
            SERVICE_CONTEXTS[service_name].append(recovery_ctx)

    logger.warning(
        f"RECOVERY COMPLET : {service_name}-{recovery_ctx} "
        f"(app + LSA deployes)"
    )
    return recovery_ctx

#========================================================

async def wait_for_pod_ready(service_name: str, context: str,
                              timeout: int = 120) -> bool:
    """
    Attend que le pod du contexte recovery soit en phase Running.
    Verifie toutes les 5 secondes jusqu'au timeout (defaut 120s).
    """
    token = await get_k8s_token()
    ssl_c = ssl.create_default_context()
    ssl_c.check_hostname = False
    ssl_c.verify_mode = ssl.CERT_NONE

    logger.info(
        f"Attente demarrage pod {service_name}-{context} "
        f"(timeout={timeout}s)..."
    )
    for attempt in range(timeout // 5):
        await asyncio.sleep(5)
        try:
            req = urllib.request.Request(
                f"{KUBERNETES_API}/api/v1/namespaces/{NAMESPACE}/pods"
                f"?labelSelector=app={service_name},context={context}",
                headers={"Authorization": f"Bearer {token}"}
            )
            resp = json.loads(
                urllib.request.urlopen(req, context=ssl_c).read().decode()
            )
            pods = resp.get("items", [])
            if pods:
                phase = pods[0].get("status", {}).get("phase", "")
                conditions = pods[0].get("status", {}).get("conditions", [])
                ready = any(
                    c.get("type") == "Ready" and c.get("status") == "True"
                    for c in conditions
                )
                logger.info(
                    f"Pod {service_name}-{context}: "
                    f"phase={phase}, ready={ready} "
                    f"(tentative {attempt+1})"
                )
                if phase == "Running" and ready:
                    return True
        except Exception as e:
            logger.warning(f"Erreur verification pod: {e}")

    logger.error(
        f"Timeout : pod {service_name}-{context} "
        f"non pret apres {timeout}s"
    )
    return False




# moteur de décision — choisit le meilleur contexte hors instance dégradée
def select_best_context(service_name: str, excluded_context: str) -> Optional[str]:
    contexts = SERVICE_CONTEXTS.get(service_name, [])
    candidates = {}
    for ctx in contexts:
        if ctx == excluded_context:
            continue
        key = f"{service_name}:{ctx}"
        report = scores_table.get(key)
        if report is None:
            continue
        age = datetime.utcnow() - datetime.fromisoformat(report.timestamp)
        if age > SCORE_TTL:
            continue
        if report.score >= ISOLATION_THRESHOLD:
            candidates[ctx] = report.score

    if not candidates:
        logger.error(f"⛔ Aucun contexte sain disponible pour {service_name}")
        return None

    best = max(candidates, key=candidates.get)
    logger.info(
        f"[DÉCISION] {service_name} → meilleur contexte = {best} "
        f"(score={candidates[best]:.4f})"
    )
    return best

@app.get('/health')
def health():
    return {
        'status': 'healthy',
        'service': 'CCA',
        'version': '3.1.0',
        'services_tracked': len(scores_table),
        'isolated_services': list(isolated_services),
        'active_routing': active_routing  
    }

# receive_score gère maintenant le format "service-name:context"
# et orchestre le basculement dynamique après isolation
@app.post('/api/scores')
async def receive_score(report: ScoreReport):

    # parser le champ service au format "service-payment:ctx-a"
    if ':' in report.service:
        service_name, context = report.service.split(':', 1)
    else:
        # Compatibilité ascendante : pas de contexte → on suppose ctx-a
        service_name = report.service
        context = 'ctx-a'

    # clé composite dans scores_table
    key = f"{service_name}:{context}"
    scores_table[key] = report

    # Gauge avec le label context
    CCA_SCORE_GAUGE.labels(
        service=service_name,
        context=context,
        status=report.status
    ).set(report.score)

    instance_key = f"{service_name}-{context}"  # ex: service-payment-ctx-a

    if report.score < ISOLATION_THRESHOLD:
        logger.warning(
            f"Score critique : {service_name} [{context}] = {report.score:.4f}"
        )
        # 1. Isoler cette instance spécifique
        await apply_isolation_policy(service_name, context)

        # 2. Trouver le meilleur remplaçant et basculer le trafic
        best_context = select_best_context(service_name, excluded_context=context)
        if best_context:
            current_active = active_routing.get(service_name)
            # Basculer seulement si l'instance active est celle qui vient d'être dégradée
            if current_active == context or current_active is None:
                await reroute_service(service_name, best_context)
        # Remplacer le else final dans receive_score par :
        else:
            logger.error(
                f"TOUS LES CONTEXTES COMPROMIS pour {service_name} — "
                f"declenchement du recovery automatique"
            )
            # Creer le pod applicatif + le LSA de recovery
            recovery_ctx = await spawn_recovery_instance(service_name)
            if recovery_ctx:
                # Attendre que le pod soit Running avant de router
                pod_ready = await wait_for_pod_ready(service_name, recovery_ctx)
                if pod_ready:
                    await reroute_service(service_name, recovery_ctx)
                    logger.warning(
                        f"RECOVERY ACTIF : {service_name} route vers "
                        f"{recovery_ctx} — LSA demarre"
                    )
                else:
                    # Pod pas pret dans les 120s — router quand meme
                    # et laisser le LSA envoyer son premier score
                    await reroute_service(service_name, recovery_ctx)
                    logger.warning(
                        f"RECOVERY route vers {recovery_ctx} "
                        f"(pod pas encore confirme Running)"
                    )
            else:
                logger.error(
                    f"ECHEC RECOVERY pour {service_name} — "
                    f"intervention manuelle requise"
                )

    elif instance_key in isolated_services:
        # utiliser instance_key au lieu de report.service
        recovery_counter[instance_key] = recovery_counter.get(instance_key, 0) + 1
        count = recovery_counter[instance_key]
        logger.info(
            f"Récupération {service_name} [{context}] : {count}/{RECOVERY_THRESHOLD} scores bons"
        )
        # vérifier aussi le seuil de score pour la réintégration
        if count >= RECOVERY_THRESHOLD and report.score >= RECOVERY_THRESHOLD_SCORE:
            await remove_isolation_policy(service_name, context)
            logger.info(
                f"✅ {service_name} [{context}] réintégré après {count} cycles consécutifs"
            )
    else:
        recovery_counter[instance_key] = 0

    return {
        'received': True,
        'service': service_name,
        'context': context,                                       
        'score': report.score,
        'active_context': active_routing.get(service_name, 'ctx-a'),  
        'isolated': instance_key in isolated_services,
        'recovery_count': recovery_counter.get(instance_key, 0)
    }

# endpoint de diagnostic du routage — pour la démo et Grafana
@app.get('/api/routing')
def get_routing_state():
    result = {}
    for service_name, contexts in SERVICE_CONTEXTS.items():
        ctx_scores = {}
        for ctx in contexts:
            key = f"{service_name}:{ctx}"
            report = scores_table.get(key)
            ctx_scores[ctx] = {
                "score": round(report.score, 4) if report else None,
                "status": report.status if report else "unknown",
                "isolated": f"{service_name}-{ctx}" in isolated_services
            }
        result[service_name] = {
            "active_context": active_routing.get(service_name, "ctx-a"),
            "contexts": ctx_scores
        }
    return {
        "routing": result,
        "routing_history": routing_history[-20:]
    }

# compose_workflow utilise le contexte actif pour chaque service
@app.get('/api/compose', response_model=WorkflowComposition)
def compose_workflow(workflow: str):
    if workflow not in WORKFLOWS:
        raise HTTPException(status_code=404, detail=f'Workflow {workflow} inconnu')
    required_services = WORKFLOWS[workflow]
    selected = []
    excluded = []
    now = datetime.utcnow()
    for service in required_services:
        # regarder le score du contexte actif, pas juste le service
        active_ctx = active_routing.get(service, 'ctx-a')
        key = f"{service}:{active_ctx}"
        report = scores_table.get(key)

        if report is None:
            excluded.append({'service': service, 'reason': 'Pas encore évalué par un LSA', 'score': None})
            continue
        report_time = datetime.fromisoformat(report.timestamp)
        if now - report_time > SCORE_TTL:
            excluded.append({'service': service, 'reason': 'Score expiré', 'score': report.score})
            continue

        instance_key = f"{service}-{active_ctx}"
        if instance_key in isolated_services:
            count = recovery_counter.get(instance_key, 0)
            excluded.append({
                'service': service,
                'reason': f'Isolé réseau - AuthorizationPolicy DENY active (récupération: {count}/{RECOVERY_THRESHOLD})',
                'score': report.score,
                'status': report.status,
                'active_context': active_ctx  
            })
        elif report.score >= ISOLATION_THRESHOLD:
            selected.append({
                'service': service,
                'score': report.score,
                'status': report.status,
                'active_context': active_ctx,  
                'components': report.components
            })
        else:
            reason = f'Score trop bas ({report.score:.4f} < {ISOLATION_THRESHOLD})'
            excluded.append({
                'service': service,
                'reason': reason,
                'score': report.score,
                'status': report.status
            })

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

# get_status affiche maintenant le contexte et si l'instance est active
@app.get('/api/status')
def get_status():
    now = datetime.utcnow()
    status_list = []
    for key, report in scores_table.items():
        # parser la clé composite
        if ':' in key:
            service_name, context = key.split(':', 1)
        else:
            service_name, context = key, 'ctx-a'

        age = (now - datetime.fromisoformat(report.timestamp)).seconds
        instance_key = f"{service_name}-{context}"
        status_list.append({
            'service': service_name,
            'context': context,                                         
            'score': report.score,
            'status': report.status,
            'components': report.components,
            'last_update_seconds': age,
            'isolated': instance_key in isolated_services,
            'active': active_routing.get(service_name) == context,    
            'recovery_count': recovery_counter.get(instance_key, 0),
            'recovery_needed': RECOVERY_THRESHOLD
        })
    status_list.sort(key=lambda x: x['score'], reverse=True)
    return {
        'services': status_list,
        'isolation_threshold': ISOLATION_THRESHOLD,
        'isolated_services': list(isolated_services),
        'active_routing': active_routing  
    }

metrics_app = make_asgi_app()
app.mount('/metrics', metrics_app)

if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8080)