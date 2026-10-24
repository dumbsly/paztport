# Shared image for every Java artifact in the POC. The jar is chosen per
# compose service via the JAR build arg, so one Dockerfile serves all of them.
FROM eclipse-temurin:21-jre

ARG JAR
WORKDIR /app
COPY ${JAR} /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
