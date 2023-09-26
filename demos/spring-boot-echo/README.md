# Spring Boot Echo

Spring boot application without authentication or authorization.  
[Gatekeeper](https://github.com/gogatekeeper/gatekeeper) is used to protect this application.

#### Local
```shell
mvn clean install spring-boot:run
```

#### Docker
```shell
docker build . -t spring-boot-echo
```