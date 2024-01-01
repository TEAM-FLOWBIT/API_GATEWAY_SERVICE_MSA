FROM openjdk:11
COPY ./target/apigateway-service-0.0.1-SNAPSHOT.jar application.jar
ENV TZ=Asia/Seoul
EXPOSE 8000

ENTRYPOINT ["java", "-jar", "-Dspring.config.name=bootstrap", "/application.jar"]

