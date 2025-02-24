FROM rust:1.85.0-alpine AS build

RUN apk update && apk add --no-cache make protobuf-dev musl-dev

WORKDIR /opt/app

COPY Cargo.toml Cargo.lock ./
COPY . .

RUN cargo build --release -p passport


FROM alpine

RUN adduser -D passport

WORKDIR /opt

COPY --from=build --chown=passport:passport /opt/app/target/release/passport .

USER passport

EXPOSE 5000
EXPOSE 3000

CMD ["./passport"]
