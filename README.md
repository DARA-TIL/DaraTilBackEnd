<div align="center">

# DaraTil Backend

**The API powering DaraTil — a platform for learning the Kazakh language and exploring Kazakhstan's regional culture.**

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Gin](https://img.shields.io/badge/Gin-1.11-008ECF?logo=gin&logoColor=white)](https://gin-gonic.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Swagger](https://img.shields.io/badge/API-Swagger-85EA2D?logo=swagger&logoColor=black)](https://swagger.io/)

</div>

## About the project

DaraTil Backend is a REST and WebSocket API for an interactive Kazakh language-learning experience. It brings lessons, tests, dictionaries, folklore, regional slang and traditions together with gamification, real-time notifications, speech practice, and AI-assisted learning.

The codebase follows a layered, domain-oriented architecture that keeps business rules independent from HTTP handlers and database implementations.

## Features

- Email/password authentication with JWT access and refresh tokens
- Google and GitHub OAuth authentication
- Lessons, question-based tests, results, and progress tracking
- Kazakh dictionary and favorite-word collections
- AI word explanations and conversational learning powered by Gemini
- Speech-test sessions and speech recognition
- Regional slang, traditions, translations, and folklore
- Achievements, XP, streaks, activity tracking, and leaderboards
- Scheduled and weekly learning events
- Real-time AI chat and notifications over WebSockets
- Subscription plans, daily usage limits, and payment workflows
- Role-protected administration endpoints
- Rate limiting, configurable origin checks, and graceful shutdown
- Interactive OpenAPI/Swagger documentation

## Tech stack

| Area | Technology |
| --- | --- |
| Language | Go 1.25 |
| HTTP API | Gin |
| Database | PostgreSQL, GORM, pgx |
| Migrations | golang-migrate |
| Authentication | JWT, Goth, Google OAuth, GitHub OAuth |
| Real-time | Gorilla WebSocket |
| AI | Google Gemini / Gen AI SDK |
| Scheduling | robfig/cron |
| Documentation | Swagger / Swaggo |
| Logging | Zap |

## Architecture

```text
.
├── cmd/
│   ├── server/          # API application entry point
│   └── migration/       # Database migration runner
├── docs/                # Generated Swagger specification
├── internal/
│   ├── application/     # Use cases, application services, and helpers
│   ├── domain/          # Domain models and repository contracts
│   ├── infrastructure/  # PostgreSQL, AI, scheduler, and logging adapters
│   ├── presentation/    # HTTP handlers, routes, middleware, and DTOs
│   ├── app/             # Dependency wiring and application lifecycle
│   └── config/          # Environment-based configuration
└── migrations/          # Versioned PostgreSQL migrations
```

Requests enter through the presentation layer, are handled by application use cases, and reach external systems through repository interfaces implemented by the infrastructure layer.

## Getting started

### Prerequisites

- [Go 1.25+](https://go.dev/doc/install)
- [PostgreSQL](https://www.postgresql.org/download/)
- A Gemini API key for AI-powered features
- Google and/or GitHub OAuth credentials if social login is required

### 1. Clone the repository

```bash
git clone https://github.com/DARA-TIL/DaraTilBackEnd.git
cd DaraTilBackEnd
```

### 2. Install dependencies

```bash
go mod download
```

### 3. Configure the environment

Create a `.env` file in the repository root:

```dotenv
# Server
PORT=8080
BASE_URL=http://localhost:8080
FRONTEND_URL=http://localhost:5173
MOBILE_URL=daraltil://auth
LOCATION=Asia/Almaty

# PostgreSQL
DATABASE_URL=postgres://postgres:postgres@localhost:5432/daratil?sslmode=disable

# JWT
JWT_ACCESS_SECRET=replace-with-a-long-random-secret
JWT_REFRESH_SECRET=replace-with-another-long-random-secret
JWT_ACCESS_EXPIRES_MIN=15
JWT_REFRESH_EXPIRES_HOURS=168

# OAuth
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# Session cookie (required at startup)
SESSION_SECRET=replace-with-a-long-random-secret
SESSION_HTTP_ONLY=true
SESSION_HTTP_SECURE=false
SESSION_HTTP_SAME_SITE=2

# AI and email
GEMINI_API_KEY=
SMTP_USER=
SMTP_PASSWORD=

# WebSocket and Swagger configuration
ALLOWED_ORIGINS=http://localhost:5173,http://localhost:8080
SWAGGER_HOST=localhost:8080
SWAGGER_SCHEME=http
```

> Do not commit `.env`. For production, use strong secrets, HTTPS, a secure session cookie, and the exact allowed origins for your clients.

OAuth callback URLs are derived from `BASE_URL`:

- `http://localhost:8080/api/auth/google/callback`
- `http://localhost:8080/api/auth/github/callback`

Add the callbacks you use to the corresponding OAuth provider configuration.

### 4. Create the database and run migrations

Create an empty PostgreSQL database matching `DATABASE_URL`, then run:

```bash
go run ./cmd/migration
```

### 5. Start the API

```bash
go run ./cmd/server
```

The API is served at `http://localhost:8080/api`.

## API documentation

With the server running, open the interactive Swagger UI:

```text
http://localhost:8080/api/swagger/index.html
```

Most endpoints require an access token:

```http
Authorization: Bearer <access-token>
```

Main API groups include `auth`, `user`, `lesson`, `test`, `dictionary`, `folklore`, `region`, `achievement`, `leaderboard`, `timeEvent`, `notifications`, `ai-chat`, `speech-tests`, `subscriptions`, and `payments`.

WebSocket connections are available at:

- `/api/ws` — real-time notifications
- `/api/ws/aiChat` — real-time AI chat

## Development

Format and verify the project before opening a pull request:

```bash
go fmt ./...
go vet ./...
go test ./...
```

If handler annotations change, regenerate the Swagger files with:

```bash
go run github.com/swaggo/swag/cmd/swag@latest init -g cmd/server/main.go
```

## Contributing

Contributions are welcome. Fork the repository, create a focused branch, make and test your changes, then open a pull request describing the problem and your solution.

For larger changes, open an issue first so the approach can be discussed.

---


