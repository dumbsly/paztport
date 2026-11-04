# Shared image for every Java artifact in the POC. The jar is chosen per
# compose service via the JAR build arg, so one Dockerfile serves all of them.
# The JRE is pinned by the digest of its multi-arch index: 25.0.4_7, as last pushed on 2026-09-18, the newest build
# pushed at least two weeks before it was chosen. Bump to 25.0.5 once its build is two weeks old.
FROM eclipse-temurin:25.0.4_7-jre@sha256:bb036ed6cfdc57e3da7c22634d15f1b840d2caf76183861c80e81ca4b5104abb

ARG JAR
WORKDIR /app
COPY ${JAR} /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
