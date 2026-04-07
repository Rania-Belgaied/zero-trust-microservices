#!/bin/bash
# generate_dataset.sh
# Génère automatiquement un dataset labelisé pour l'entraînement ML

CYCLES_PER_SCENARIO=20   # 20 cycles × 30s = 10 minutes par scénario
CYCLE_DURATION=35        # attendre un peu plus que 30s pour être sûr

set_attack_type() {
    local attack_type=$1
    echo "=== Scénario : $attack_type ==="
    for svc in lsa-service-auth lsa-service-orders lsa-service-payment lsa-service-notification; do
        kubectl set env deployment/$svc -n agents ATTACK_TYPE=$attack_type
    done
    sleep 10  # attendre le redémarrage
}

collect_samples() {
    local n=$1
    local description=$2
    echo "  Collecte de $n échantillons — $description"
    for i in $(seq 1 $n); do
        sleep $CYCLE_DURATION
        count=$(kubectl exec -n agents \
            $(kubectl get pods -n agents -l app=lsa-service-payment \
            -o jsonpath='{.items[0].metadata.name}') \
            -- wc -l /data/security_dataset.csv 2>/dev/null | awk '{print $1}')
        echo "  Cycle $i/$n — $count lignes dans le dataset"
    done
}

echo "======================================"
echo "  GÉNÉRATION DU DATASET DE SÉCURITÉ"
echo "======================================"
echo "Cycles par scénario : $CYCLES_PER_SCENARIO"
echo "Durée totale estimée : ~$(( CYCLES_PER_SCENARIO * 7 * CYCLE_DURATION / 60 )) minutes"
echo ""

# ─────────────────────────────────────────
# SCÉNARIO 0 — État sain (label=0)
# ─────────────────────────────────────────
set_attack_type "none"
collect_samples $((CYCLES_PER_SCENARIO * 2)) "état sain (plus d'échantillons car cas majoritaire)"

# ─────────────────────────────────────────
# SCÉNARIO 1 — Intrusion Falco (label=1)
# ─────────────────────────────────────────
set_attack_type "falco_shell"
# Déclencher l'intrusion en boucle pendant la collecte
for i in $(seq 1 $CYCLES_PER_SCENARIO); do
    kubectl exec -n app deploy/service-payment -c service-payment -- \
        sh -c 'echo intrusion && id' 2>/dev/null &
    sleep $CYCLE_DURATION
done
collect_samples 0 "intrusion Falco déjà en cours"

# ─────────────────────────────────────────
# SCÉNARIO 2 — OPA compromise (label=1)
# ─────────────────────────────────────────
set_attack_type "opa_compromised"
kubectl patch configmap opa-policies -n security --patch \
    '{"data":{"microservices-authz.rego":"package microservices.authz\ndefault allow = true\nviolations[msg] { false; msg = \"\" }\ncompliance_score = 1.0\n"}}'
kubectl rollout restart deployment/opa-v2 -n security
sleep 15
collect_samples $CYCLES_PER_SCENARIO "OPA compromise"
# Restaurer OPA
kubectl create configmap opa-policies \
    --from-file=microservices-authz.rego=/home/rania/zero-trust-microservices/policies/microservices-authz.rego \
    -n security --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment/opa-v2 -n security

# ─────────────────────────────────────────
# SCÉNARIO 3 — mTLS dégradé (label=1)
# ─────────────────────────────────────────
set_attack_type "mtls_permissive"
kubectl apply -f - << EOF
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: payment-permissive
  namespace: app
spec:
  selector:
    matchLabels:
      app: service-payment
  mtls:
    mode: PERMISSIVE
EOF
collect_samples $CYCLES_PER_SCENARIO "mTLS dégradé"
kubectl delete peerauthentication payment-permissive -n app

# ─────────────────────────────────────────
# SCÉNARIO 4 — Crash service (label=1)
# ─────────────────────────────────────────
set_attack_type "service_crash"
for i in $(seq 1 $CYCLES_PER_SCENARIO); do
    kubectl scale deployment service-payment -n app --replicas=0
    # Générer du trafic vers le service crashé
    for j in $(seq 1 5); do
        kubectl exec -n app deploy/service-orders -c service-orders -- \
            python3 -c "
import urllib.request, urllib.error
try:
    urllib.request.urlopen('http://service-payment.app.svc.cluster.local:8080/health')
except: pass
" 2>/dev/null &
    done
    sleep $CYCLE_DURATION
    kubectl scale deployment service-payment -n app --replicas=1
    sleep 15
done

# ─────────────────────────────────────────
# SCÉNARIO 5 — Lecture fichier sensible (label=1)
# ─────────────────────────────────────────
set_attack_type "falco_sensitive_file"
for i in $(seq 1 $CYCLES_PER_SCENARIO); do
    kubectl exec -n app deploy/service-payment -c service-payment -- \
        sh -c 'cat /etc/passwd' 2>/dev/null &
    sleep $CYCLE_DURATION
done

# ─────────────────────────────────────────
# SCÉNARIO 6 — Multi-vecteurs (label=1)
# ─────────────────────────────────────────
set_attack_type "multi_attack"
for i in $(seq 1 $CYCLES_PER_SCENARIO); do
    # Falco + crash simultanés
    kubectl exec -n app deploy/service-payment -c service-payment -- \
        sh -c 'echo intrusion' 2>/dev/null &
    kubectl scale deployment service-payment -n app --replicas=0
    sleep $CYCLE_DURATION
    kubectl scale deployment service-payment -n app --replicas=1
    sleep 15
done

# ─────────────────────────────────────────
# RETOUR À L'ÉTAT NORMAL
# ─────────────────────────────────────────
set_attack_type "none"
echo ""
echo "======================================"
echo "  GÉNÉRATION TERMINÉE"
echo "======================================"

# Récupérer le dataset
kubectl cp agents/$(kubectl get pods -n agents -l app=lsa-service-payment \
    -o jsonpath='{.items[0].metadata.name}'):/data/security_dataset.csv \
    ~/zero-trust-microservices/dataset/security_dataset.csv

echo "Dataset sauvegardé dans : ~/zero-trust-microservices/dataset/security_dataset.csv"
wc -l ~/zero-trust-microservices/dataset/security_dataset.csv
