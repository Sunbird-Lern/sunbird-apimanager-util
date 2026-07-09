ARG DHI_IMAGE_DEV=dhi.io/eclipse-temurin:8-jdk-debian13-dev 
ARG DHI_IMAGE_RUNTIME=dhi.io/eclipse-temurin:8-debian13

FROM dhi.io/busybox:1.38.0-alpine3.24 as shell

# ---- prep stage
FROM ${DHI_IMAGE_DEV} AS build

ENV APP_HOME=/opt/app
RUN mkdir -p $APP_HOME
WORKDIR $APP_HOME

COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

COPY build/libs/adminutil-*.jar adminutil.jar

# ---- runtime stage
FROM ${DHI_IMAGE_RUNTIME}
COPY --from=shell /lib/ld-musl-x86_64.so.1 /lib/ld-musl-x86_64.so.1
COPY --from=shell /bin/busybox /bin/sh
COPY --from=build /opt/app /opt/app
# EXPOSE 4000

WORKDIR /opt/app

ENTRYPOINT ["./docker-entrypoint.sh"]