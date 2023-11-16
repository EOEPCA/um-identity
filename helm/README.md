### Create Sealed secrets

```shell
export ADMIN_PASSWORD=
export PROXY_CLIENT_SECRET=
export PROXY_ENCRYPTION_KEY=
export KC_DB_PASSWORD=
export PGPASSWORD=
export POSTGRES_PASSWORD=${KC_DB_PASSWORD}

kubectl create secret generic identity-api -n um --dry-run --from-literal=ADMIN_PASSWORD=${ADMIN_PASSWORD} -o yaml | kubeseal --controller-name=eoepca-sealed-secrets --controller-namespace=infra --format yaml > identity-api-sealedsecret.yaml
kubectl create secret generic identity-gatekeeper -n um --dry-run --from-literal=PROXY_CLIENT_SECRET=${PROXY_CLIENT_SECRET} --from-literal=PROXY_ENCRYPTION_KEY=${PROXY_ENCRYPTION_KEY} -o yaml | kubeseal --controller-name=eoepca-sealed-secrets --controller-namespace=infra --format yaml > identity-gatekeeper-sealedsecret.yaml
kubectl create secret generic identity-keycloak -n um --dry-run --from-literal=KEYCLOAK_ADMIN_PASSWORD=${ADMIN_PASSWORD} --from-literal=KC_DB_PASSWORD=${KC_DB_PASSWORD} -o yaml | kubeseal --controller-name=eoepca-sealed-secrets --controller-namespace=infra --format yaml > identity-keycloak-sealedsecret.yaml
kubectl create secret generic identity-postgres -n um --dry-run --from-literal=POSTGRES_PASSWORD=${POSTGRES_PASSWORD} --from-literal=PGPASSWORD=${PGPASSWORD} -o yaml | kubeseal --controller-name=eoepca-sealed-secrets --controller-namespace=infra --format yaml > identity-postgres-sealedsecret.yaml

cat identity-api-sealedsecret.yaml | kubeseal --validate --controller-name=eoepca-sealed-secrets --controller-namespace=infra
cat identity-gatekeeper-sealedsecret.yaml | kubeseal --validate --controller-name=eoepca-sealed-secrets --controller-namespace=infra
cat identity-keycloak-sealedsecret.yaml | kubeseal --validate --controller-name=eoepca-sealed-secrets --controller-namespace=infra
cat identity-postgres-sealedsecret.yaml | kubeseal --validate --controller-name=eoepca-sealed-secrets --controller-namespace=infra
```