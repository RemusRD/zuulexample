FROM openjdk:8-jdk-alpine

MAINTAINER Remus Richard

VOLUME /tmp

ADD "target/spring-cloud-gateway-sample-0.0.1-SNAPSHOT.jar" spring-cloud-gateway-sample.jar

ENV JAVA_OPTS=""

ENTRYPOINT [ "sh","-c","java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar spring-cloud-gateway-sample.jar" ]