FROM gcc:latest AS build

WORKDIR /app

RUN apt-get update && apt-get install -y make g++ gcc

ADD ./include ./include
ADD ./sqlite ./sqlite
ADD ./src ./src
ADD ./Makefile .

RUN make

# Запуск ---------------------------------------

FROM ubuntu:latest


WORKDIR /app

COPY --from=build /app/build/server .

ENTRYPOINT ["/app/server"]