# fastapi-authz-jwt

A small helper library for FastAPI that provides JWT decoding and scope-based authorization.

Features

- Decode and validate JWTs using keys fetched by `pyjwt-key-fetcher`.
- Integrates with FastAPI `Security` dependencies and `SecurityScopes` for scope checks.
- Lightweight, dependency-injection friendly design suitable for tests.

## Quickstart

1. Install the package via pip:

```bash
pip install fastapi-authz-jwt
```

1. Use in your FastAPI app:

```python
from fastapi import FastAPI, Security
from fastapi_authz_jwt.auth import TokenData, require_scopes

app = FastAPI()

@app.get("/public")
async def public():
 return {"message": "public"}

@app.get("/protected")
async def protected(token: TokenData = Security(require_scopes)):
 return {"user": token.username}
```

## Testing

Run the test suite with coverage (this project uses `uv run pytest`):

```bash
uv run pytest
```

Notes

- The package exposes a `decode_token` dependency that lazily initializes a key fetcher to avoid creating async clients at import time.
- The codebase is organized for easy testing; tests mock the key fetcher where appropriate.

Using Security Scopes

You can require scopes on endpoints and chain scope-requiring dependencies. Example:

```python
from fastapi import FastAPI, Security
from fastapi_authz_jwt.auth import TokenData, require_scopes

app = FastAPI()

@app.get("/items")
async def read_items(token: TokenData = Security(require_scopes, scopes=["items:read"])):
 return {"items": ["item1"], "user": token.username}

# Reusable dependency that requires admin scope
async def require_admin(token: TokenData = Security(require_scopes, scopes=["admin"])) -> TokenData:
 return token

@app.get("/admin/users")
async def admin_users(token: TokenData = Security(require_admin, scopes=["users:read"])):
 # SecurityScopes aggregates ["admin", "users:read"]
 return {"users": ["user1", "user2"], "admin": token.username}
```

This ensures the request bearer token contains both `admin` and `users:read` scopes.
