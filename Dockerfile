# lokaj: a single binary. Configuration is mounted at /etc/lokaj/lokaj.toml.
FROM rust:1.95-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/lokaj /usr/local/bin/lokaj
EXPOSE 6432 9930
ENTRYPOINT ["/usr/local/bin/lokaj"]
CMD ["/etc/lokaj/lokaj.toml"]
