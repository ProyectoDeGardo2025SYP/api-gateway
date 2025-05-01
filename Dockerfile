FROM eclipse-temurin:21-jdk as builder
RUN apt-get update && apt-get install -y unzip
WORKDIR /app
COPY . .
RUN chmod +x ./gradlew

RUN ./gradlew clean bootJar --no-daemon
FROM eclipse-temurin:21-jdk-alpine
EXPOSE 8889
COPY --from=builder /app/build/libs/*.jar /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]