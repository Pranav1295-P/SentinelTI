from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.deps import CurrentUser, SessionDep
from app.core.config import settings
from app.core.security import COOKIE_NAME, create_access_token, hash_password, verify_password
from app.models import User
from app.schemas.auth import Credentials, RegisterRequest, UserOut
from app.services.ratelimit import enforce_rate_limit

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_session_cookie(response: Response, user: User) -> None:
    response.set_cookie(
        COOKIE_NAME, create_access_token(str(user.id)), max_age=settings.access_token_minutes * 60,
        httponly=True, samesite="strict", secure=settings.cookie_secure, path="/api",
    )


@router.post("/login", response_model=UserOut)
async def login(body: Credentials, request: Request, response: Response, session: SessionDep) -> User:
    client = request.client.host if request.client else "unknown"
    await enforce_rate_limit("login", f"{client}:{body.email.lower()}", settings.login_rate_per_minute)
    user = await session.scalar(select(User).where(User.email == body.email.lower()))
    valid = verify_password(body.password, user.password_hash if user else None)
    if not valid or user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    _set_session_cookie(response, user)
    return user


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, request: Request, response: Response, session: SessionDep) -> User:
    if not settings.allow_registration:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Registration is disabled. Ask an administrator for access.")
    client = request.client.host if request.client else "unknown"
    await enforce_rate_limit("register", client, settings.login_rate_per_minute)
    user = User(email=body.email.lower(), password_hash=hash_password(body.password))
    session.add(user)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="This email is already registered") from None
    _set_session_cookie(response, user)
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/api")


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser) -> User:
    return user
