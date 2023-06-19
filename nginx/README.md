# Nginx

```shell
docker build -t nginx .
docker run -v letsencrypt:/etc/letsencrypt --name nginx -ti -p 8080:80 nginx sh
certbot certonly --nginx -d auth.proxy.develop.eoepca.org
```
