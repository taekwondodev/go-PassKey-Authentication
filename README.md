<div align="center">

# go-PassKey-Authentication

![Go Version](https://img.shields.io/badge/Go-1.25.0-blue.svg)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![Flyway](https://img.shields.io/badge/Flyway-CC0200?logo=flyway&logoColor=white)](https://flywaydb.org/)
[![SonarCloud](https://img.shields.io/badge/SonarCloud-F3702A?logo=sonarcloud&logoColor=white)](https://sonarcloud.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/taekwondodev/go-PassKey-Authentication)](https://goreportcard.com/report/github.com/taekwondodev/go-PassKey-Authentication)

A modern passwordless authentication system built with Go and WebAuthn.

</div>

## Overview

This project implements a complete passkey authentication flow with JWT tokens, PostgreSQL database, Redis token blacklisting, and Docker containerization. Features secure logout with token invalidation and automatic cleanup. Support only one origin/bundle-id as client for testing purposes.

## Tech Stack

| Category             | Technology             |
|----------------------|------------------------|
| **Language**         | Go 1.25.0              |
| **Database**         | PostgreSQL 15+         |
| **Session**          | Redis 7+               |
| **Authentication**   | WebAuthn (go-webauthn) |
| **Tokens**           | JWT (golang-jwt)       |
| **Database Access**  | SQLC + pgx/v5          |
| **Containerization** | Docker                 |
| **Migrations**       | Flyway                 |

## Api Endpoints

Complete API documentation is available in OpenAPI 3.0 format:

- [![Open in Swagger Editor](https://img.shields.io/badge/Swagger-Editor-%23Clojure?style=for-the-badge&logo=swagger)](https://editor.swagger.io/?url=https://raw.githubusercontent.com/taekwondodev/go-PassKey-Authentication/main/internal/api/openapi.yaml)

- [Raw OpenAPI Spec](internal/api/openapi.yaml)

## Quick Start

### Prerequisites

- Go 1.25.0+ (locally)
- Docker

### Example Configuration

```bash
JWT_SECRET=$(openssl rand -hex 32)
ORIGIN_FRONTEND=http://localhost:3000
URL_BACKEND=http://localhost:8080
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=passkey_db
postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}?sslmode=disable
REDIS_URL=redis://redis:6379
HASH_SALT=$(openssl rand -hex 32)
```

### Using Docker Compose (recommended)

```bash
git clone https://github.com/taekwondodev/go-PassKey-Authentication.git # Clone the repository

cd go-PassKey-Authentication # Change to the project directory

docker buildx bake && docker compose up # Start the application
```

## Project Structure

```txt
go-PassKey-Authentication/
├── 📁 cmd/                    # Application entrypoint
├── 📁 internal/
│   ├── 📁 api/               # HTTP handlers and routing
│   ├── 📁 config/            # Configuration management
│   ├── 📁 controller/        # HTTP controllers
│   ├── 📁 customerrors/      # Custom error definitions
│   ├── 📁 db/                # Generated database code (SQLC)
│   ├── 📁 dto/               # Data Transfer Objects
│   ├── 📁 middleware/        # HTTP middleware
│   ├── 📁 models/            # Domain models
│   ├── 📁 repository/        # Data access layer
│   └── 📁 service/           # Business logic
├── 📁 migrations/            # Database migrations
├── 📁 pkg/                   # Shared utilities
├── 📁 query/                 # SQL queries (SQLC)
├── 🐳 Dockerfile
├── 🐳 compose.yaml
├── 🏗️ bake.hcl
└── ⚙️ sqlc.yaml
```

## Security Features

- **FIDO2/WebAuthn** compliance
- **JWT** access and refresh tokens
- **Redis token blacklisting** for secure logout and token invalidation
- **Token rotation** on refresh to prevent replay attacks
- **CORS** protection with configurable origins
- **CSRF** protection for stateful sessions
- **SQL injection** prevention with prepared statements
- **ARGON2ID token hashing** for secure Redis storage
- **Automatic TTL cleanup** of blacklisted tokens
- **Graceful error** handling
- **Request validation** and sanitization

## Testing (using Docker recommended)

To run the unit tests run the command in the main directory:

```bash
docker buildx bake -f bake.hcl test --progress=plain
```
