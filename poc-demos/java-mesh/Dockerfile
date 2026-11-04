# Shared image for every Java artifact in the POC. The jar is chosen per
# compose service via the JAR build arg, so one Dockerfile serves all of them.
# The JRE is pinned by the digest of its multi-arch index: 25.0.4.1_1-jre as last pushed by 2026-10-21, on
# 2026-10-17 (docker-library/repo-info, repos/eclipse-temurin/remote/25.0.4.1_1-jre.md at fd12a9e). Move to 25.0.5
# once a 25.0.5 image has been pushed for two weeks (25.0.5_8-jre was first pushed on 2026-10-29).
FROM eclipse-temurin:25.0.4.1_1-jre@sha256:dbb43d81099eec91e0800226ed2296d03146ee7857165b95112372ad0d67e87f

ARG JAR
WORKDIR /app
COPY ${JAR} /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
