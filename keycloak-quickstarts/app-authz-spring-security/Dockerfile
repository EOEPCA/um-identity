FROM eclipse-temurin:8-jdk-alpine as builder

WORKDIR /home/app

COPY pom.xml .
COPY maven-settings.xml .

WORKDIR app-authz-spring-security

COPY app-authz-spring-security/mvnw .
COPY app-authz-spring-security/.mvn .mvn
COPY app-authz-spring-security/pom.xml .
COPY app-authz-spring-security/src src

RUN sed -i 's/\r$//' ./mvnw

RUN chmod +x mvnw && \
    ./mvnw package spring-boot:repackage && \
    cp /home/app/app-authz-spring-security/target/app-authz-spring-security-21.1.1.jar /app.jar

################################
### stage 2 - package java  ###
################################
FROM eclipse-temurin:8-jre-alpine

COPY --from=builder app.jar /home/app/app.jar

EXPOSE 7070

ENTRYPOINT [ "java", "-Xmx512m", "-jar", "/home/app/app.jar" ]
