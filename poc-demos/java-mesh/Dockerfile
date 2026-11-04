# Shared image for every Java artifact in the POC. The jar is chosen per
# compose service via the JAR build arg, so one Dockerfile serves all of them.
# The JRE is pinned by the digest of its multi-arch index: 25.0.4_7-jre as pushed on 2026-09-18
# (docker-library/repo-info, repos/eclipse-temurin/remote/25.0.4_7-jre.md at c3947b3). Move to 25.0.5 once a
# 25.0.5 image has been pushed for two weeks (25.0.5_8-jre was first pushed on 2026-10-29).
FROM eclipse-temurin:25.0.4_7-jre@sha256:bb036ed6cfdc57e3da7c22634d15f1b840d2caf76183861c80e81ca4b5104abb

ARG JAR
WORKDIR /app
COPY ${JAR} /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
