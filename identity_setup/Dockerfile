# run keycloak-setup to configure Keycloak
FROM python:alpine
WORKDIR /app
COPY identity_setup/ identity_setup/
COPY utils/ identity_setup/src/utils/
RUN pip install -r identity_setup/requirements.txt
RUN python identity_setup/src/main.py
