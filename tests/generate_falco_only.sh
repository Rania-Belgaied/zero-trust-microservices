#!/bin/bash
CYCLES_PER_SCENARIO=20
CYCLE_DURATION=35

POD=$(kubectl get pods -n agents -l app=lsa-service-payment \
  -o jsonpath='{.items[0].metadata.name}')

echo "=== Scénario : falco_shell ==="
for svc in lsa-service-auth lsa-service-orders lsa-service-payment lsa-service-notification; do
    kubectl set env deployment/$svc -n agents ATTACK_TYPE=falco_shell
done
sleep 15  # attendre le redémarrage des pods

for i in $(seq 1 $CYCLES_PER_SCENARIO); do
    # Déclencher l'intrusion
    kubectl exec -n app deploy/service-payment -c service-payment -- \
        sh -c 'echo intrusion && id' 2>/dev/null
    sleep $CYCLE_DURATION
    
    # Compter les lignes
    POD=$(kubectl get pods -n agents -l app=lsa-service-payment \
        -o jsonpath='{.items[0].metadata.name}')
    count=$(kubectl exec -n agents $POD -c lsa \
        -- wc -l /data/security_dataset.csv 2>/dev/null | awk '{print $1}')
    echo "  Cycle $i/$CYCLES_PER_SCENARIO — $count lignes"
done

# Retour état normal
for svc in lsa-service-auth lsa-service-orders lsa-service-payment lsa-service-notification; do
    kubectl set env deployment/$svc -n agents ATTACK_TYPE=none
done

echo "=== Scénario falco_shell terminé ==="

# Copier le dataset
POD=$(kubectl get pods -n agents -l app=lsa-service-payment \
    -o jsonpath='{.items[0].metadata.name}')
kubectl cp agents/$POD:/data/security_dataset.csv \
    ~/zero-trust-microservices/dataset/security_dataset.csv \
    -c lsa
echo "Dataset mis à jour : $(wc -l < ~/zero-trust-microservices/dataset/security_dataset.csv) lignes"
