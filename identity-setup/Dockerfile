# run keycloak-setup to configure Keycloak
FROM python:alpine
WORKDIR /app
COPY identity-setup/ identity-setup/
COPY utils/ identity-setup/src/utils/
RUN pip install -r identity-setup/requirements.txt
RUN python identity-setup/src/main.py
