# =====================================================================
# Estágio 1: Builder oficial Rust (rápido, estável e com toolchain pronta)
# =====================================================================
FROM docker.io/library/rust:1-slim as builder

WORKDIR /opt/app-root/src

# Cache de dependências do Cargo
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src target/release/loganalizer* target/release/deps/loganalizer*

# Copia o código-fonte real e compila o binário de alta performance
COPY src ./src
RUN cargo build --release

# =====================================================================
# Estágio 2: Runtime Seguro UBI9 Micro/Minimal (Non-root OpenShift UID)
# =====================================================================
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

WORKDIR /opt/app-root/src

# Copia o binário compilado e os assets estáticos/templates
COPY --from=builder /opt/app-root/src/target/release/loganalizer /opt/app-root/src/loganalizer
COPY templates ./templates
COPY static ./static

# Cria diretório de banco de dados e dados com permissões do OpenShift (GID 0)
RUN mkdir -p /opt/app-root/src/data && \
    chown -R 1001:0 /opt/app-root/src && \
    chmod -R g=u /opt/app-root/src

# Usuário non-root padrão recomendado pelo OpenShift
USER 1001

EXPOSE 8080

ENV PORT=8080 \
    DB_PATH=/opt/app-root/src/data/logs_analysis.db \
    RUST_LOG=info

CMD ["/opt/app-root/src/loganalizer"]
