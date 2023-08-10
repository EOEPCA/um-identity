# OAuth2 Proxy Example
 
This example app shows how to use OAuth2 Proxy with Keycloak.

**Prerequisites:** 
* [Docker](https://docs.docker.com/get-docker/)
* [Docker Compose](https://docs.docker.com/compose/install/)

### Start the Application

To start the applciatin run:
```shell
docker compose up
```  
Go to Keycloak Admin UI and add a new client for oauth2-proxy.  
Copy and paste client id and client secret into .env
Re-run docker compose:
```shell
docker compose up
```

## Components

This example uses the following components:

* Web App - Demo application based on Spring boot. Exposes a single endpoint http://localhost/echo
* [Keycloak](https://www.keycloak.org/) - OIDC Identity Provider
* [OAuth2 Proxy](https://oauth2-proxy.github.io/oauth2-proxy/docs/) - Authentication Proxy to add authentication and authorization to Web App
* [Nginx](https://www.nginx.com/) - Web server to manage user requests. http://localhost/logout.html to logout
* [Redis](https://redis.io/) - In-memory data store for session data storage
* [Postgres](https://www.postgresql.org/) - Database for Keycloak

## License

Apache 2.0, see [LICENSE](LICENSE).
