FROM eclipse-temurin:23

WORKDIR /app

COPY target/auth-*.jar app.jar

EXPOSE 8081

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
