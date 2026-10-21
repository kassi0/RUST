# 🚀 IIS Log Analyzer - Rust High-Performance Multi-Core Engine

Aplicação Web de alta performance desenvolvida em **Rust (Axum + Rayon + SQLite/Rusqlite)** para ingestão paralela ultrarrápida, análise estatística e visualização em tempo real de arquivos de log do **Microsoft IIS (formato W3C Extended Log)**.

Migrado e otimizado a partir do projeto original em Python Flask ([kassi0/loganalizer](https://github.com/kassi0/loganalizer)).

---

## ⚡ Benefícios da Versão em Rust

- **Processamento Multi-Core Paralelo (Rayon)**: Dividindo o arquivo em fatias e processando simultaneamente por thread/core com zero-copy string parsing.
- **Servidor Web Assíncrono com Tokio + Axum**: Capacidade para milhares de requisições concorrentes com baixíssimo consumo de memória RAM (< 30 MB).
- **Sem Dependência de Interpretador**: Binário nativo compilado de alta performance.
- **Dashboard Analítico Completo**:
  - Gráficos interativos (Chart.js): Volume de requisições x erros, códigos de status e métodos HTTP.
  - Agrupamentos por minuto (URI, Client-IP e Método HTTP) com filtros rápidos e ordenação dinâmica.
  - Filtros avançados com paginação ágil no banco de dados SQLite (WAL Mode).
  - Retenção automática de 24h para limpezas de disco, com opção de persistência manual.

---

## 🛠️ Como Subir a Aplicação

### 1. Pré-requisitos
- **Rust Toolchain**: `cargo` e `rustc` (gerenciados via `rustup`).
- Compilador C (GCC via MSYS2 / MinGW-w64 ou Visual Studio C++ Build Tools).

### 2. Executar em Modo de Desenvolvimento
No terminal (PowerShell ou Bash) na raiz do projeto:

```powershell
cargo run
```

O servidor iniciará automaticamente em: **`http://localhost:5000`**

### 3. Compilar em Modo de Produção (Velocidade Máxima)
Para obter a máxima velocidade de parsing de logs:

```powershell
cargo build --release
.\target\release\loganalizer.exe
```

### 4. Variáveis de Ambiente Opcionais
- `PORT`: Porta HTTP (padrão: `5000`).
- `DB_PATH`: Caminho do arquivo de banco SQLite (padrão: `logs_analysis.db`).

Exemplo alterando porta:
```powershell
$env:PORT="8080"; cargo run
```

---

## 📁 Estrutura do Projeto

```
.
├── Cargo.toml                # Dependências Rust (Axum, Rayon, Rusqlite, Tokio, MiniJinja)
├── src/
│   ├── main.rs               # Rotas Axum, middlewares, engine de templates e startup
│   ├── models.rs             # Modelos de dados e serialização JSON/SQL
│   ├── parser.rs             # Motor Multi-Core de leitura e parsing de logs W3C (Rayon)
│   └── db.rs                 # Camada de dados SQLite com WAL mode, consultas analíticas e retenção
├── static/
│   ├── css/style.css         # UI moderna (Dark Mode, Glassmorphism, Tailwind/Inter inspirada)
│   └── js/
│       ├── main.js           # Upload assíncrono com barra de progresso
│       ├── dashboard.js      # Gráficos Chart.js e métricas por minuto
│       └── logs.js           # Tabela com busca, paginação e modais de detalhes
└── templates/
    ├── base.html             # Layout base com sidebar responsiva
    ├── index.html            # Upload e seleção de núcleos da CPU
    ├── dashboard.html        # Dashboard analítico com KPIs
    ├── history.html          # Histórico de análises e retenção
    └── logs.html             # Visualizador avançado de registros
```

---

## 🐳 Executando com Docker

Crie uma imagem leve de produção:

```dockerfile
FROM rust:1.80-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/loganalizer /app/loganalizer
COPY --from=builder /app/templates /app/templates
COPY --from=builder /app/static /app/static
EXPOSE 5000
CMD ["/app/loganalizer"]
```

Build e execução:
```bash
docker build -t loganalizer-rust .
docker run -p 5000:5000 loganalizer-rust
```
