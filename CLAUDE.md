# Pishro Auth — Standalone OIDC Identity Provider

## Project Overview
Standalone OpenID Connect identity provider for the Pishro Party ecosystem. Provides passkey-based (WebAuthn) authentication and issues OIDC tokens consumed by the Civic Compass Portal and HRMS ERP.

## Tech Stack
- **Runtime:** .NET 10, C#, Minimal APIs
- **Database:** PostgreSQL with EF Core
- **Auth:** OpenIddict (OIDC server), Fido2NetLib (WebAuthn/passkeys)
- **Architecture:** Clean Architecture (Domain, Application, Infrastructure, Server)

## Architecture
```
pishro-auth/
  src/
    Pishro.Auth.Domain/           # Entities (User, PasskeyCredential)
    Pishro.Auth.Application/      # DTOs, service interfaces
    Pishro.Auth.Infrastructure/   # EF Core, Fido2 service, OpenIddict seed
    Pishro.Auth.Server/           # Minimal API entry point (port 5300)
```

## OIDC Clients
- **portal** (Civic Compass Portal) — redirects to portal.pishro.party / localhost:3100
- **hrms** (HRMS ERP) — redirects to erp.pishro.party / localhost:3000

## Commands

### Start infrastructure
```bash
docker compose up -d
```

### Start server
```bash
cd src/Pishro.Auth.Server && dotnet run
```

### EF Core migration
```bash
dotnet ef migrations add {Name} \
  --project src/Pishro.Auth.Infrastructure \
  --startup-project src/Pishro.Auth.Server \
  --output-dir Persistence/Migrations
```

## Ports
| Service | Port |
|---------|------|
| Auth Server | 5300 |
| PostgreSQL | 5433 (maps to 5432) |

## URLs
- **Production:** https://auth.pishro.party
- **Login:** /login.html
- **Register:** /register.html
- **OIDC Discovery:** /.well-known/openid-configuration
