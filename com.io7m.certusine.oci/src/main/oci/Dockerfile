ARG certusine_version

FROM docker.io/library/alpine:3.16.0
FROM docker.io/library/eclipse-temurin:17.0.3_7-jre-alpine

ENV PATH="/certusine/bin:/sbin:/bin:/usr/sbin:/usr/bin:/opt/java/openjdk/bin"
ENV LOOSELEAF_HOME="/certusine"

COPY certusine /certusine

LABEL "org.opencontainers.image.authors"="Mark Raynsford"
LABEL "org.opencontainers.image.description"="ACME Client"
LABEL "org.opencontainers.image.licenses"="ISC"
LABEL "org.opencontainers.image.source"="https://www.github.com/io7m/certusine"
LABEL "org.opencontainers.image.title"="Certusine"
LABEL "org.opencontainers.image.url"="https://www.io7m.com/software/certusine"
LABEL "org.opencontainers.image.version"="$certusine_version"

VOLUME "/certusine/etc"

CMD ["/certusine/bin/certusine"]
