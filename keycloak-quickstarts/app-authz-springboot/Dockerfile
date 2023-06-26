FROM eclipse-temurin:17-jdk-alpine as builder

WORKDIR /home/app

COPY pom.xml .
COPY maven-settings.xml .

WORKDIR app-authz-springboot

COPY app-authz-springboot/mvnw .
COPY app-authz-springboot/.mvn .mvn
COPY app-authz-springboot/pom.xml .
COPY app-authz-springboot/src src
RUN ls ..

RUN sed -i 's/\r$//' ./mvnw

RUN chmod +x mvnw && \
    ./mvnw install -DskipTests && \
    cp /home/app/app-authz-springboot/target/*.jar /app.jar

################################
### stage 2 - package java  ###
################################
FROM eclipse-temurin:17-jre-alpine

COPY --from=builder app.jar /home/app/app.jar

EXPOSE 8080

ENTRYPOINT [ "java", "-Xmx512m", "-jar", "/home/app/app.jar" ]
