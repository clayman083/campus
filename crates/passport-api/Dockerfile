FROM rust:1.85.0-alpine AS chef

RUN apk update && apk add --no-cache make musl-dev
RUN cargo install cargo-chef

WORKDIR /opt/app


FROM chef AS planner
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json


FROM chef AS builder

RUN apk update && apk add --no-cache make protobuf-dev musl-dev
COPY --from=planner /opt/app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release -p passport-api


FROM alpine AS runtime

RUN adduser -D passport

WORKDIR /opt

COPY --from=builder --chown=passport:passport /opt/app/target/release/passport .

USER passport

EXPOSE 5000
EXPOSE 3000

CMD ["./passport"]
