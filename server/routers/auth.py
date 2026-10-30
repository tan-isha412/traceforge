from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from server import audit, auth, ratelimit
from server.config import settings
from server.database import get_db
from server.models import User
from server.schemas import UTCDatetime

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    username: str
    role: str


class LoginOut(UserOut):
    token: str
    expires_at: UTCDatetime


class NewUser(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=auth.MIN_PASSWORD_LENGTH, max_length=256)
    role: str = "investigator"


@router.get("/config")
def config():
    """Lets the dashboard know whether to show the login screen."""
    return {"auth_enabled": settings.auth_enabled}


@router.post("/login", response_model=LoginOut)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    keys = (f"user:{body.username.lower()}", f"addr:{request.client.host if request.client else '?'}")
    wait = ratelimit.retry_after(*keys)
    if wait is not None:
        audit.record(db, body.username, "auth.login_throttled")
        db.commit()
        raise HTTPException(status_code=429, detail="Too many failed logins. Try again later.", headers={"Retry-After": str(wait)})
    user = auth.authenticate(db, body.username, body.password)
    if user is None:
        ratelimit.failed(*keys)
        audit.record(db, body.username, "auth.login_failed")
        db.commit()
        raise HTTPException(status_code=401, detail="Wrong username or password.")
    ratelimit.succeeded(keys[0])
    token, expires = auth.start_session(db, user)
    audit.record(db, user.username, "auth.login")
    db.commit()
    return LoginOut(username=user.username, role=user.role, token=token, expires_at=expires)


@router.post("/logout", status_code=204)
def logout(authorization: str | None = Header(default=None), db: Session = Depends(get_db), user: User | None = Depends(auth.current_user)):
    token = auth._bearer(authorization)
    if token:
        auth.end_session(db, token)
    audit.record(db, auth.actor(user), "auth.logout")
    db.commit()


@router.get("/me", response_model=UserOut)
def me(user: User | None = Depends(auth.current_user)):
    if user is None:  # logins switched off
        return UserOut(username="anonymous", role="admin")
    return UserOut(username=user.username, role=user.role)


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User | None = Depends(auth.require_role("admin"))):
    return [UserOut(username=u.username, role=u.role) for u in db.query(User).order_by(User.username)]


@router.post("/users", response_model=UserOut, status_code=201)
def add_user(body: NewUser, db: Session = Depends(get_db), user: User | None = Depends(auth.require_role("admin"))):
    try:
        created = auth.create_user(db, body.username, body.password, body.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit.record(db, auth.actor(user), "user.create", "user", created.id, username=created.username, role=created.role)
    db.commit()
    return UserOut(username=created.username, role=created.role)
