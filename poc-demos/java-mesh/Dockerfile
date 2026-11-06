# Shared image for every Java artifact in the POC. The jar is chosen per
# compose service via the JAR build arg, so one Dockerfile serves all of them.
# The JRE is pinned by the digest of its multi-arch index: 25.0.5_8-jre, first pushed on 2026-10-29.
FROM eclipse-temurin:25.0.5_8-jre@sha256:ecdc0adb37bde1a281c4d245a3cd535004b1fc8322d560f5b09463b248c81df0

ARG JAR
WORKDIR /app
COPY ${JAR} /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
