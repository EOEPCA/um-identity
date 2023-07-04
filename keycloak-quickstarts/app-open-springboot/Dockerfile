FROM eclipse-temurin:8-jdk-alpine as builder

WORKDIR /home/app

COPY pom.xml .
COPY maven-settings.xml .

WORKDIR app-open-springboot

COPY app-open-springboot/mvnw .
COPY app-open-springboot/.mvn .mvn
COPY app-open-springboot/pom.xml .
COPY app-open-springboot/src src

RUN sed -i 's/\r$//' ./mvnw

RUN chmod +x mvnw && \
    ./mvnw package spring-boot:repackage && \
    cp /home/app/app-open-springboot/target/app-open-springboot-21.1.1.jar /app.jar

################################
### stage 2 - package java  ###
################################
FROM eclipse-temurin:8-jre-alpine

COPY --from=builder app.jar /home/app/app.jar

EXPOSE 7071

ENTRYPOINT [ "java", "-Xmx512m", "-jar", "/home/app/app.jar" ]
