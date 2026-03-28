# agents/lsa/collectors.py
# Module de collecte des données de sécurité depuis OPA, Falco, Istio, Keycloak

import asyncio
import httpx
import os
import logging

logger = logging.getLogger(__name__)

# Configuration depuis les variables d'environnement
OPA_URL        = os.getenv('OPA_URL', 'http://opa.security.svc.cluster.local:8181')
PROMETHEUS_URL = os.getenv('PROMETHEUS_URL', 'http://prometheus.monitoring.svc.cluster.local:9090')
KEYCLOAK_URL   = os.getenv('KEYCLOAK_URL', 'http://keycloak.security.svc.cluster.local:8080')
TARGET_SERVICE = os.getenv('TARGET_SERVICE', 'service-payment')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'zero-trust-project')
KEYCLOAK_CLIENT= os.getenv('KEYCLOAK_CLIENT', 'lsa-agent')
KEYCLOAK_SECRET= os.getenv('KEYCLOAK_SECRET', 'lsa-agent-secret-2026')
FALCO_URL      = os.getenv('FALCO_URL', 'http://falco-falcosidekick.security.svc.cluster.local:2801')

class DataCollector:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=10.0)

    # ─────────────────────────────────────────────
    # C : Confidentialité — état mTLS via Istio
    # ─────────────────────────────────────────────
    async def collect_mtls_status(self) -> float:
        try:
            query = (
                f'sum(rate(istio_requests_total{{'
                f'destination_service_name="{TARGET_SERVICE}",'
                f'connection_security_policy="mutual_tls"}}[5m])) or vector(0)'
            )
            resp_mtls = await self.client.get(
                f'{PROMETHEUS_URL}/api/v1/query',
                params={'query': query}
            )
            data_mtls = resp_mtls.json()

            query_total = (
                f'sum(rate(istio_requests_total{{'
                f'destination_service_name="{TARGET_SERVICE}"}}[5m])) or vector(0)'
            )
            resp_total = await self.client.get(
                f'{PROMETHEUS_URL}/api/v1/query',
                params={'query': query_total}
            )
            data_total = resp_total.json()

            mtls_result  = data_mtls['data']['result']
            total_result = data_total['data']['result']

            mtls_rate  = float(mtls_result[0]['value'][1])  if mtls_result  else 0.0
            total_rate = float(total_result[0]['value'][1]) if total_result else 0.0

            if total_rate == 0:
                return 1.0
            score = min(1.0, mtls_rate / total_rate)
            logger.info(f'mTLS score pour {TARGET_SERVICE}: {score:.3f}')
            return score

        except Exception as e:
            logger.warning(f'Erreur collecte mTLS: {e}')
            return 0.5

    # ─────────────────────────────────────────────
    # I : Intégrité — violations OPA
    # ─────────────────────────────────────────────
    async def collect_opa_violations(self) -> float:
        try:

            unauthorized_calls = {
                'service-auth': [
                    {'source': 'service-notification', 'dest': 'service-auth',    'method': 'POST'},
                    {'source': 'service-notification', 'dest': 'service-auth',    'method': 'GET'},
                    {'source': 'service-payment',      'dest': 'service-auth',    'method': 'POST'},
                ],
                'service-orders': [
                    {'source': 'service-notification', 'dest': 'service-orders',  'method': 'GET'},
                    {'source': 'service-notification', 'dest': 'service-orders',  'method': 'POST'},
                    {'source': 'service-payment',      'dest': 'service-orders',  'method': 'GET'},
                    {'source': 'service-auth',         'dest': 'service-orders',  'method': 'GET'},
                ],
                'service-payment': [
                    {'source': 'service-notification', 'dest': 'service-payment', 'method': 'POST'},
                    {'source': 'service-notification', 'dest': 'service-payment', 'method': 'GET'},
                    {'source': 'service-auth',         'dest': 'service-payment', 'method': 'POST'},
                ],
                'service-notification': [
                    {'source': 'service-notification', 'dest': 'service-notification', 'method': 'POST'},
                    {'source': 'service-orders',       'dest': 'service-notification', 'method': 'POST'},
                    {'source': 'service-auth',         'dest': 'service-notification', 'method': 'GET'},
                ],
            }

            authorized_calls = {
                'service-auth': [
                    {'source': 'service-orders',  'dest': 'service-auth', 'method': 'GET'},
                    {'source': 'service-orders',  'dest': 'service-auth', 'method': 'POST'},
                    {'source': 'service-payment', 'dest': 'service-auth', 'method': 'GET'},
                ],
                'service-orders': [
                    {'source': 'service-orders', 'dest': 'service-payment', 'method': 'GET'},
                    {'source': 'service-orders', 'dest': 'service-payment', 'method': 'POST'},
                ],
                'service-payment': [
                    {'source': 'service-orders',  'dest': 'service-payment',      'method': 'GET'},
                    {'source': 'service-orders',  'dest': 'service-payment',      'method': 'POST'},
                    {'source': 'service-payment', 'dest': 'service-notification', 'method': 'POST'},
                ],
                'service-notification': [
                    {'source': 'service-payment', 'dest': 'service-notification', 'method': 'POST'},
                    {'source': 'service-auth',    'dest': 'service-notification', 'method': 'POST'},
                ],
            }

            violations_count = 0
            
            for call in unauthorized_calls.get(TARGET_SERVICE, []):
                resp = await self.client.post(
                    f'{OPA_URL}/v1/data/microservices/authz',
                    json={'input': {
                        'source_service':      call['source'],
                        'destination_service': call['dest'],
                        'http_method':         call['method']
                    }}
                )
                result = resp.json().get('result', {})
                # Si allow=True pour un appel non autorisé → violation !
                if result.get('allow', False):
                    violations_count += 1
                    logger.warning(
                        f'VIOLATION INTÉGRITÉ: {call["source_service"]} -> {call["dest"]}'
                        f'via {call["method"]} autorisé alors qu interdit!'
                    )

        
            for call in authorized_calls.get(TARGET_SERVICE, []):
                resp = await self.client.post(
                    f'{OPA_URL}/v1/data/microservices/authz',
                    json={'input': {
                        'source_service':      call['source'],
                        'destination_service': call['dest'],
                        'http_method':         call['method']
                    }}
                )
                result = resp.json().get('result', {})
                if not result.get('allow', True):
                    violations_count += 1
                    logger.warning(
                        f'VIOLATION INTÉGRITÉ: {call["source"]} -> {call["dest"]} '
                        f'via {call["method"]} bloqué alors qu autorisé!'
                    )
            score = max(0.0, 1.0 - (violations_count * 0.3))
            logger.info(
                f'OPA violations pour {TARGET_SERVICE}: {violations_count}, score I: {score}'
            )
            return float(score)

        except Exception as e:
            logger.warning(f'Erreur collecte OPA: {e}')
            return 0.5

    # ─────────────────────────────────────────────
    # B : Comportement — alertes Falco via Prometheus
    # ─────────────────────────────────────────────
    async def collect_falco_alerts(self) -> float:
        try:
            # Chercher les alertes Falco pour notre service
            # via les métriques Falcosidekick exposées à Prometheus
            queries = {
                'critical': (
                    f'increase(falcosecurity_falcosidekick_falco_events_total{{'
                    f'priority_raw="critical",k8s_ns_name="app", k8s_pod_name=~"{TARGET_SERVICE}.*"}}[5m]) or vector(0)'
                ),
                'error': (
                    f'increase(falcosecurity_falcosidekick_falco_events_total{{'
                    f'priority_raw="error",k8s_ns_name="app", k8s_pod_name=~"{TARGET_SERVICE}.*"}}[5m]) or vector(0)'
                ),
                'warning': (
                    f'increase(falcosecurity_falcosidekick_falco_events_total{{'
                    f'priority_raw="warning",k8s_ns_name="app", k8s_pod_name=~"{TARGET_SERVICE}.*"}}[5m]) or vector(0)'
                ),
            }
            weights = {'critical': 0.3, 'error': 0.2, 'warning': 0.1}
            total_penalty = 0.0

            for priority, query in queries.items():
                resp = await self.client.get(
                    f'{PROMETHEUS_URL}/api/v1/query',
                    params={'query': query}
                )
                data   = resp.json()
                result = data['data']['result']
                count  = float(result[0]['value'][1]) if result else 0.0
                total_penalty += count * weights[priority]
                logger.info(f'Falco {priority} pour {TARGET_SERVICE}: {count}')

            score = max(0.0, 1.0 - total_penalty)
            logger.info(f'Falco score pour {TARGET_SERVICE}: {score:.3f}')
            return score

        except Exception as e:
            logger.warning(f'Erreur collecte Falco: {e}')
            return 0.5

    # ─────────────────────────────────────────────
    # P : Policy compliance — score OPA global
    # ─────────────────────────────────────────────
    async def collect_policy_compliance(self) -> float:
        try:
            # Test d'un appel autorisé
            test_cases = [
                # Appels AUTORISÉS
                {'source': 'service-orders',  'dest': 'service-auth',         'method': 'GET',  'expected': True},
                {'source': 'service-orders',  'dest': 'service-auth',         'method': 'POST', 'expected': True},
                {'source': 'service-orders',  'dest': 'service-payment',      'method': 'GET',  'expected': True},
                {'source': 'service-orders',  'dest': 'service-payment',      'method': 'POST', 'expected': True},
                {'source': 'service-payment', 'dest': 'service-notification', 'method': 'POST', 'expected': True},
                {'source': 'service-payment', 'dest': 'service-auth',         'method': 'GET',  'expected': True},
                {'source': 'service-auth',    'dest': 'service-notification', 'method': 'POST', 'expected': True},
                # Appels NON AUTORISÉS
                {'source': 'service-notification', 'dest': 'service-payment',      'method': 'POST', 'expected': False},
                {'source': 'service-notification', 'dest': 'service-orders',       'method': 'GET',  'expected': False},
                {'source': 'service-notification', 'dest': 'service-auth',         'method': 'GET',  'expected': False},
                {'source': 'service-auth',         'dest': 'service-orders',       'method': 'GET',  'expected': False},
                {'source': 'service-auth',         'dest': 'service-payment',      'method': 'POST', 'expected': False},
                {'source': 'service-orders',       'dest': 'service-notification', 'method': 'POST', 'expected': False},
            ]

            correct = 0
            total   = len(test_cases)

            for tc in test_cases:
                resp = await self.client.post(
                    f'{OPA_URL}/v1/data/microservices/authz',
                    json={'input': {
                        'source_service':      tc['source'],
                        'destination_service': tc['dest'],
                        'http_method':         tc['method']
                    }}
                )
                result  = resp.json().get('result', {})
                allowed = result.get('allow', False)
                if allowed == tc['expected']:
                    correct += 1
                else:
                    logger.warning(
                        f'Policy non conforme: {tc["source"]} -> {tc["dest"]} '
                        f'attendu={tc["expected"]} obtenu={allowed}'
                    )


            score = round(correct / total, 3)
            logger.info(f'Policy compliance pour {TARGET_SERVICE}: {score:.3f} ({correct}/{total})')
            return score

        except Exception as e:
            logger.warning(f'Erreur collecte policy compliance: {e}')
            return 0.5

    # ─────────────────────────────────────────────
    # R : Reliability — taux d'erreur HTTP
    # ─────────────────────────────────────────────
    async def collect_reliability(self) -> float:
        try:
            query_errors = (
                f'sum(rate(istio_requests_total{{'
                f'destination_service_name="{TARGET_SERVICE}",'
                f'response_code=~"5.."}}[5m])) or vector(0)'
            )
            query_total = (
                f'sum(rate(istio_requests_total{{'
                f'destination_service_name="{TARGET_SERVICE}"}}[5m])) or vector(0)'
            )

            resp_err   = await self.client.get(
                f'{PROMETHEUS_URL}/api/v1/query',
                params={'query': query_errors}
            )
            resp_total = await self.client.get(
                f'{PROMETHEUS_URL}/api/v1/query',
                params={'query': query_total}
            )

            errors = resp_err.json()['data']['result']
            total  = resp_total.json()['data']['result']

            error_rate = float(errors[0]['value'][1]) if errors else 0.0
            total_rate = float(total[0]['value'][1])  if total  else 1.0

            if total_rate == 0:
                return 1.0

            error_ratio = error_rate / total_rate
            score       = max(0.0, 1.0 - (error_ratio * 10))
            logger.info(f'Reliability score pour {TARGET_SERVICE}: {score:.3f}')
            return score

        except Exception as e:
            logger.warning(f'Erreur collecte reliability: {e}')
            return 0.5

    # ─────────────────────────────────────────────
    # Collecte complète en parallèle
    # ─────────────────────────────────────────────
    async def collect_all(self) -> dict:
        C, I, B, P, R = await asyncio.gather(
            self.collect_mtls_status(),
            self.collect_opa_violations(),
            self.collect_falco_alerts(),
            self.collect_policy_compliance(),
            self.collect_reliability(),
        )
        return {'C': C, 'I': I, 'B': B, 'P': P, 'R': R}

    async def close(self):
        await self.client.aclose()