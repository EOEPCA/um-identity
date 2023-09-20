# Auth Proxy Example
 
This example shows how to use Gatekeeper with Keycloak to authorize users' access to an unprotected service.

**Prerequisites:** 
* [Docker](https://docs.docker.com/get-docker/)
* [Docker Compose](https://docs.docker.com/compose/install/)

### Start the Application

To start the applciatin run:
```shell
docker compose up -d
```

### Components

This example uses the following components:

* Web App - Demo application based on Spring boot. 
  * [localhost:7070](localhost:7070) is open to every user.
  * [localhost:7070/admin](localhost:7070/admin) is permited to Admin and Eric. Access to Alice is denied.
* [Keycloak](https://www.keycloak.org/) - OIDC Identity Provider
* [Gatekeeper](https://gogatekeeper.github.io/gatekeeper) - Auth Proxy to add authentication and authorization to Web App
* [Postgres](https://www.postgresql.org/) - Database for Keycloak


### Documentation

- https://gogatekeeper.github.io/gatekeeper/userguide/
- https://gogatekeeper.github.io/gatekeeper/configuration/
