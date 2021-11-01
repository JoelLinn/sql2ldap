FROM rust:alpine3.14 as builder_deps

WORKDIR /usr/src/sql2ldap

RUN apk add --no-cache libc-dev

COPY Cargo.toml Cargo.lock ./

# Prebuilt dependencies
RUN mkdir src ; \
    echo "fn main() {}" > src/main.rs ; \
    cargo build --release ; \
    rm -rf src


FROM builder_deps as builder

COPY . .

RUN touch src/main.rs ; \
    cargo install --path .


FROM alpine:3.14

COPY --from=builder /usr/local/cargo/bin/sql2ldap /usr/local/bin/sql2ldap

ENTRYPOINT [ "/usr/local/bin/sql2ldap" ]
