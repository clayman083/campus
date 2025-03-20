FROM --platform=$BUILDPLATFORM rust:1.85.0-alpine AS build

RUN apk update && apk add --no-cache make protobuf-dev musl-dev

RUN rustup target add wasm32-unknown-unknown
RUN cargo install trunk && cargo install -f wasm-bindgen-cli

WORKDIR /opt/app

COPY Cargo.toml Cargo.lock ./
COPY . .

WORKDIR /opt/app/crates/passport-web

RUN trunk build --release


FROM nginx:alpine

COPY --from=build /opt/app/crates/passport-web/dist /usr/share/nginx/html
COPY ./crates/passport-web/conf/nginx.conf /etc/nginx/conf.d/default.conf
