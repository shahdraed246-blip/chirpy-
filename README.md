# Chirpy

Chirpy is a Twitter-like social network back-end built with **TypeScript**, **Express 5**, and **PostgreSQL**, with no front-end framework. It is a REST API with user accounts, JWT authentication, refresh tokens, and a payment webhook.

## Why it's interesting

- Authentication with **argon2** password hashing, **JWT** access tokens, and revocable refresh tokens
- Authorization: users can only edit or delete their own resources
- **Drizzle ORM** with automatic migrations on startup
- Webhook handling secured with an API key
- Centralized error handling with custom error classes
- Unit tests with **Vitest**

## Requirements

- Node.js 22.14+
- PostgreSQL 15+

## Setup

1. Clone the repo and install dependencies:

```bash
   git clone <your-repo-url>
   cd chirpy
   npm install
```

2. Create a database named `chirpy`.

3. Create a `.env` file in the project root:

```
   DB_URL="postgres://USER:PASSWORD@localhost:5432/chirpy?sslmode=disable"
   PORT=8080
   PLATFORM=dev
   JWT_SECRET="<long random string>"
   POLKA_KEY="<your polka api key>"
```

   Generate a secret with `openssl rand -base64 64`.

4. Build and run (migrations run automatically on startup):

```bash
   npm run dev
```

5. Run the tests:

```bash
   npm test
```

## API

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/api/healthz` | Readiness check | - |
| POST | `/api/users` | Create a user | - |
| PUT | `/api/users` | Update own email and password | Bearer JWT |
| POST | `/api/login` | Log in, returns access and refresh tokens | - |
| POST | `/api/refresh` | New access token from a refresh token | Bearer refresh token |
| POST | `/api/revoke` | Revoke a refresh token | Bearer refresh token |
| POST | `/api/chirps` | Create a chirp (max 140 chars) | Bearer JWT |
| GET | `/api/chirps` | List chirps. Query: `authorId`, `sort=asc\|desc` | - |
| GET | `/api/chirps/:chirpId` | Get one chirp | - |
| DELETE | `/api/chirps/:chirpId` | Delete own chirp | Bearer JWT |
| POST | `/api/polka/webhooks` | Payment provider webhook (Chirpy Red) | ApiKey |
| GET | `/admin/metrics` | Visit counter page | - |
| POST | `/admin/reset` | Reset data (dev only) | - |

## Example

```bash
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{"email": "lane@example.com", "password": "04234"}'
```

## Project structure

```
src/
  index.ts          server, routes, handlers
  auth.ts           hashing, JWT, token helpers
  config.ts         environment config
  db/
    schema.ts       Drizzle tables
    queries/        database queries
    migrations/     generated SQL migrations
```

## Notes

Built while following the Boot.dev "Learn HTTP Servers in TypeScript" course.
