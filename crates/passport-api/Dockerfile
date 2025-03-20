FROM --platform=$BUILDPLATFORM rust:1.85.0-alpine AS chef

RUN apk update && apk add --no-cache musl-dev openssl-dev zig
RUN cargo install --locked cargo-zigbuild cargo-chef
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

WORKDIR /opt/app


FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

RUN apk update && apk add --no-cache make protobuf-dev musl-dev
COPY --from=planner /opt/app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json --zigbuild \
    --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl
COPY . .
RUN cargo zigbuild -r -p passport-api --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl && \
    mkdir /opt/linux && \
    cp target/aarch64-unknown-linux-musl/release/passport /opt/linux/arm64 && \
    cp target/x86_64-unknown-linux-musl/release/passport /opt/linux/amd64


FROM alpine AS runtime

RUN adduser -D passport

WORKDIR /opt

ARG TARGETPLATFORM

COPY --from=builder --chown=passport:passport /opt/${TARGETPLATFORM} /opt/passport

USER passport

EXPOSE 5000
EXPOSE 3000

CMD ["./passport"]
