# build oauth2-proxy binary
FROM golang:alpine AS oauth2-proxy
RUN apk --no-cache add curl
RUN curl --output-dir github.com/oauth2-proxy/oauth2-proxy/v7.4.0/ \
     https://github.com/oauth2-proxy/oauth2-proxy/releases/download/v7.4.0/oauth2-proxy-v7.4.0.linux-amd64.tar.gz
RUN go install github.com/oauth2-proxy/oauth2-proxy/v7@latest

# run identity-setup to configure the Identity
FROM python:alpine as auth-proxy-server
WORKDIR /app
COPY identity-setup/ identity_setup/
COPY utils/ identity_setup/src/utils/
RUN pip install -r identity_setup/requirements.txt
RUN python identity_setup/src/main.py

# build final image to setup nginx and run oauth2-proxy
FROM alpine
# Setup nginx
RUN apk add certbot certbot-nginx
RUN mkdir /etc/letsencrypt
COPY default.conf /etc/nginx/conf.d/default.conf
# schedule a cronjob to renew certs on first day of each month at 12 pm
RUN echo "0 12 1 * * /usr/bin/certbot renew --quiet"; >> /var/spool/cron/crontabs/root
# run oauth2-proxy
COPY --from=oauth2-proxy /go/bin/oauth2-proxy oauth2-proxy
COPY --from=auth-proxy-server /app/identity_setup/conf/keycloak.cfg .
EXPOSE 4180
ENTRYPOINT ["./oauth2-proxy", "--config=keycloak.cfg"]
