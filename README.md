# fastapi-security-jwt

[![CI](https://github.com/CEBasile/fastapi-security-jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/CEBasile/fastapi-security-jwt/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/CEBasile/fastapi-security-jwt/graph/badge.svg?token=RTKC596GZJ)](https://codecov.io/gh/CEBasile/fastapi-security-jwt)
[![Version](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fpkg.eziobasile.com%2Fpypi%2Ffastapi-security-jwt%2Fjson&query=%24.info.version)](https://pkg.eziobasile.com)

A small helper library for FastAPI that provides JWT decoding and scope-based authorization. Integrates directly with FastAPI's Security and SecurityScopes system.

**Features:**

- Zero middleware!
- 100% Test Coverage!
- Fully async compatible!

## Quickstart

Install the package via pip:

```bash
pip install fastapi-security-jwt
```

Use in your FastAPI app:

```python
from fastapi import FastAPI, Security
from fastapi_security_jwt import JWTBearer, TokenData

# Instantiate same as FastAPI docs with your OpenID Connect URL
jwt_bearer = JWTBearer(openid_connect_url="https://<your_url>/.well-known/openid-configuration")

app = FastAPI()

@app.get("/public")
async def public():
    return {"message": "public"}

@app.get("/protected")
async def protected(token: TokenData = Security(jwt_bearer, scopes=["user"])):
    return {"user": token.username}
```

## Using Security Scopes

You can require scopes on endpoints and chain scope dependencies. Example:

```python
# Reusable dependency that requires admin scope
requires_admin = Security(jwt_bearer, scopes=["admin"])

# When combined with an upstream Security that also requires "admin",
# FastAPI will aggregate scopes and `JWTBearer` will validate them.
@app.get("/admin/users", token: TokenData = Security(requires_admin, scopes=["users:read"]))
async def admin_users():
    return {"users": ["user1", "user2"], "emails": ["user1@local", "user2@local"]}
```

This ensures the request bearer token contains both `admin` and `users:read` scopes.
