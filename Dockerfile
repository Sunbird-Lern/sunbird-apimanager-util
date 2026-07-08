ARG DHI_IMAGE_DEV=dhi.io/eclipse-temurin:8-jdk-debian13-dev 

FROM ${DHI_IMAGE_DEV}

ENV APP_HOME=/opt/app
RUN mkdir -p $APP_HOME
WORKDIR $APP_HOME

COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

COPY build/libs/adminutil-*.jar adminutil.jar

ENTRYPOINT ["./docker-entrypoint.sh"]
