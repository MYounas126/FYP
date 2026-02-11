"""
Authentication endpoints.

Handles user login, logout, and token refresh.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from loguru import logger

from app.db.session import get_db
from app.models.user import User
from app.schemas.user import Token, UserResponse, UserCreate
from app.core.security import (
    verify_password,
    create_access_token,
    create_refresh_token,
    verify_token,
    get_password_hash
)

# Import limiter from rate_limit module
from app.core.rate_limit import limiter

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Dependency to get the current authenticated user.

    Args:
        token: JWT access token
        db: Database session

    Returns:
        The authenticated user

    Raises:
        HTTPException: If token is invalid or user not found
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    user_id = verify_token(token, token_type="access")
    if user_id is None:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )

    return user


async def get_current_admin_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Dependency to ensure user is an admin.

    Args:
        current_user: The authenticated user

    Returns:
        The admin user

    Raises:
        HTTPException: If user is not an admin
    """
    if current_user.role.value != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
) -> Token:
    """
    Authenticate user and return JWT tokens.

    Rate limited to 5 requests per minute per IP to prevent brute force attacks.

    Args:
        request: FastAPI request object (for rate limiting)
        form_data: OAuth2 password request form
        db: Database session

    Returns:
        Access and refresh tokens

    Raises:
        HTTPException: If credentials are invalid
    """
    # Find user by username
    result = await db.execute(
        select(User).where(User.username == form_data.username)
    )
    user = result.scalar_one_or_none()

    if user is None or not verify_password(form_data.password, user.hashed_password):
        logger.warning(f"Failed login attempt for username: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )

    # Create tokens
    access_token = create_access_token(
        subject=str(user.id),
        additional_claims={"role": user.role.value}
    )
    refresh_token = create_refresh_token(subject=str(user.id))

    logger.info(f"User logged in: {user.username}")

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: str,
    db: AsyncSession = Depends(get_db)
) -> Token:
    """
    Refresh access token using refresh token.

    Args:
        refresh_token: Valid refresh token
        db: Database session

    Returns:
        New access and refresh tokens

    Raises:
        HTTPException: If refresh token is invalid
    """
    user_id = verify_token(refresh_token, token_type="refresh")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )

    # Create new tokens
    new_access_token = create_access_token(
        subject=str(user.id),
        additional_claims={"role": user.role.value}
    )
    new_refresh_token = create_refresh_token(subject=str(user.id))

    return Token(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer"
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
) -> UserResponse:
    """
    Get current authenticated user information.

    Args:
        current_user: The authenticated user

    Returns:
        User information
    """
    return UserResponse.model_validate(current_user)


@router.post("/register", response_model=UserResponse)
async def register_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
) -> UserResponse:
    """
    Register a new user.

    Args:
        user_data: User registration data
        db: Database session

    Returns:
        Created user information

    Raises:
        HTTPException: If email or username already exists
    """
    # Check if email exists
    result = await db.execute(select(User).where(User.email == user_data.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Check if username exists
    result = await db.execute(select(User).where(User.username == user_data.username))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )

    # Create user
    # SECURITY: Force default role to "observer" - ignore any user-provided role
    # Admin roles must be assigned by existing admins through a separate endpoint
    user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        role="observer"  # Always default, ignore user input to prevent privilege escalation
    )

    db.add(user)
    await db.commit()
    await db.refresh(user)

    logger.info(f"New user registered: {user.username}")

    return UserResponse.model_validate(user)
