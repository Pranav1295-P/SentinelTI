import uuid
from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_session
from app.core.security import COOKIE_NAME, decode_access_token
from app.models import Analysis, User

SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def get_current_user(
    session: SessionDep,
    cookie_token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> User:
    """Browsers authenticate with an HttpOnly cookie; API clients may send a Bearer token."""
    token = cookie_token
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:]
    user_id = decode_access_token(token) if token else None
    user = None
    if user_id:
        try:
            user = await session.get(User, uuid.UUID(user_id))
        except ValueError:
            user = None
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


async def get_owned_analysis(analysis_id: uuid.UUID, session: SessionDep, user: CurrentUser) -> Analysis:
    """404 rather than 403, so ids of other users' analyses cannot be probed."""
    row = await session.get(Analysis, analysis_id)
    if row is None or row.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Analysis not found")
    return row


OwnedAnalysis = Annotated[Analysis, Depends(get_owned_analysis)]
