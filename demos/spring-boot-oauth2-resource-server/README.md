# Spring Boot OAuth2 Resource Server

Spring boot application with resource endpoints protected by OAuth2 tokens from Keycloak provider.
[Gatekeeper](https://github.com/gogatekeeper/gatekeeper) is used to authorize users and pass access_token to access resources from this application.

#### Local
```shell
mvn clean install spring-boot:run
```

#### Docker
```shell
docker build . -t spring-boot-oauth2-resource-server
```