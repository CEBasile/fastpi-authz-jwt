"""FastAPI application with JWT authentication endpoints."""

from fastapi import FastAPI, Security

from src.fastapi_authz_jwt.auth import TokenData, require_scopes

app = FastAPI()


@app.get("/public")
async def public_endpoint():
    """No authentication required"""
    return {"message": "Public endpoint"}


@app.get("/protected")
async def protected_endpoint(token: TokenData = Security(require_scopes)):
    """Requires valid JWT, no specific scopes"""
    return {"message": "Protected endpoint", "user": token.username, "all_scopes": token.groups}


@app.get("/items")
async def read_items(token: TokenData = Security(require_scopes, scopes=["items:read"])):
    """Requires 'items:read' scope"""
    return {"items": ["item1", "item2"], "user": token.username}


@app.post("/items")
async def create_item(
    item_name: str, token: TokenData = Security(require_scopes, scopes=["items:write"])
):
    """Requires 'items:write' scope"""
    return {"message": f"Item {item_name} created", "created_by": token.username}


@app.delete("/items/{item_id}")
async def delete_item(
    item_id: int,
    token: TokenData = Security(require_scopes, scopes=["items:write", "items:delete"]),
):
    """Requires BOTH 'items:write' AND 'items:delete' scopes"""
    return {"message": f"Item {item_id} deleted", "deleted_by": token.username}


# Example of chaining dependencies with SecurityScopes
async def require_admin(token: TokenData = Security(require_scopes, scopes=["admin"])) -> TokenData:
    """Reusable dependency that requires admin scope"""
    return token


@app.get("/admin/stats")
async def admin_stats(token: TokenData = Security(require_admin)):
    """
    Requires 'admin' scope (via require_admin dependency)
    SecurityScopes aggregates scopes from the chain
    """
    return {"stats": {"total_users": 100}, "admin": token.username}


@app.get("/admin/users")
async def admin_users(token: TokenData = Security(require_admin, scopes=["users:read"])):
    """
    Requires BOTH 'admin' (from require_admin) AND 'users:read' scopes
    SecurityScopes automatically aggregates: ["admin", "users:read"]
    """
    return {"users": ["user1", "user2"], "admin": token.username}


@app.delete("/admin/users/{user_id}")
async def delete_user(
    user_id: int, token: TokenData = Security(require_admin, scopes=["users:delete"])
):
    """
    Requires BOTH 'admin' AND 'users:delete' scopes
    """
    return {"message": f"User {user_id} deleted", "deleted_by": token.username}
