from typing import Dict, List, Optional, Tuple, Type

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Body, status
from httpx_oauth.integrations.fastapi import OAuth2AuthorizeCallback
from httpx_oauth.oauth2 import BaseOAuth2, OAuth2Token
from pydantic import BaseModel

from fastapi_users import models, schemas
from fastapi_users.authentication import AuthenticationBackend, Authenticator, Strategy
from fastapi_users.exceptions import UserAlreadyExists, UserNotExists
from fastapi_users.jwt import SecretType, decode_jwt, generate_jwt
from fastapi_users.manager import BaseUserManager, UserManagerDependency
from fastapi_users.router.common import ErrorCode, ErrorModel

STATE_TOKEN_AUDIENCE = "fastapi-users:oauth-state"

class OAuth2AuthorizeResponse(BaseModel):
    authorization_url: str


def generate_state_token(
    data: Dict[str, str], secret: SecretType, lifetime_seconds: int = 3600
) -> str:
    data["aud"] = STATE_TOKEN_AUDIENCE
    return generate_jwt(data, secret, lifetime_seconds)


def get_oauth_router(
    oauth_client: BaseOAuth2,
    backend: AuthenticationBackend[models.UP, models.ID],
    get_user_manager: UserManagerDependency[models.UP, models.ID],
    state_secret: SecretType,
    redirect_url: Optional[str] = None,
    associate_by_email: bool = False,
    is_verified_by_default: bool = False,
) -> APIRouter:
    """Generate a router with the OAuth routes."""
    router = APIRouter()
    callback_route_name = f"oauth:{oauth_client.name}.{backend.name}.callback"

    if redirect_url is not None:
        oauth2_authorize_callback = OAuth2AuthorizeCallback(
            oauth_client,
            redirect_url=redirect_url,
        )
    else:
        oauth2_authorize_callback = OAuth2AuthorizeCallback(
            oauth_client,
            route_name=callback_route_name,
        )

    @router.get(
        "/authorize",
        name=f"oauth:{oauth_client.name}.{backend.name}.authorize",
        response_model=OAuth2AuthorizeResponse,
    )
    async def authorize(
        request: Request, scopes: List[str] = Query(None)
    ) -> OAuth2AuthorizeResponse:
        if redirect_url is not None:
            authorize_redirect_url = redirect_url
        else:
            authorize_redirect_url = str(request.url_for(callback_route_name))

        state_data: Dict[str, str] = {}
        state = generate_state_token(state_data, state_secret)
        authorization_url = await oauth_client.get_authorization_url(
            authorize_redirect_url,
            state,
            scopes,
        )

        return OAuth2AuthorizeResponse(authorization_url=authorization_url)

    @router.get(
        "/callback",
        name=callback_route_name,
        description="The response varies based on the authentication backend used.",
        responses={
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            "INVALID_STATE_TOKEN": {
                                "summary": "Invalid state token.",
                                "value": None,
                            },
                            ErrorCode.LOGIN_BAD_CREDENTIALS: {
                                "summary": "User is inactive.",
                                "value": {"detail": ErrorCode.LOGIN_BAD_CREDENTIALS},
                            },
                        }
                    }
                },
            },
        },
    )
    async def callback(
        request: Request,
        access_token_state: Tuple[OAuth2Token, str] = Depends(
            oauth2_authorize_callback
        ),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
        strategy: Strategy[models.UP, models.ID] = Depends(backend.get_strategy),
    ):
        token, state = access_token_state
        account_id, account_email = await oauth_client.get_id_email(
            token["access_token"]
        )

        if account_email is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.OAUTH_NOT_AVAILABLE_EMAIL,
            )

        try:
            decode_jwt(state, state_secret, [STATE_TOKEN_AUDIENCE])
        except jwt.DecodeError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        try:
            user = await user_manager.oauth_callback(
                oauth_client.name,
                token["access_token"],
                account_id,
                account_email,
                token.get("expires_at"),
                token.get("refresh_token"),
                request,
                associate_by_email=associate_by_email,
                is_verified_by_default=is_verified_by_default,
            )
        except UserAlreadyExists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.OAUTH_USER_ALREADY_EXISTS,
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.LOGIN_BAD_CREDENTIALS,
            )

        # Authenticate
        response = await backend.login(strategy, user)
        await user_manager.on_after_login(user, request, response)
        return response

    @router.post(
        "/token-login",
        # response_model=user_schema,  # Use a relevant schema for your user model
        name=f"oauth:{oauth_client.name}.{backend.name}.token-login",
        description="Login a user with an id_token shared from the frontend.",
        responses={
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            "INVALID_ID_TOKEN": {
                                "summary": "Invalid ID token.",
                                "value": {"detail": "Invalid ID token."},
                            },
                        }
                    }
                },
            },
        },
    )
    async def token_login(
        request: Request,
        id_token: str = Body(..., embed=True),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
        strategy: Strategy[models.UP, models.ID] = Depends(backend.get_strategy),
    ):
        # Step 1: Verify the id_token with the provider
        try:
            account_id, account_email, expires_at = await oauth_client.verify_token(id_token)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid ID token.",
            )

        # Step 2: Check if the email is provided
        if account_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.OAUTH_NOT_AVAILABLE_EMAIL,
            )

        # Step 3: Find or create the user
        try:
            user = await user_manager.get_by_oauth_account(oauth_client.name, account_id)
        except UserNotExists:
            user = await user_manager.oauth_callback(
                oauth_client.name,
                id_token,
                account_id,
                account_email,
                expires_at,
                None,
                request,
                associate_by_email=associate_by_email,
                is_verified_by_default=is_verified_by_default,
            )

        # Step 4: Ensure user is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.LOGIN_BAD_CREDENTIALS,
            )

        # Step 5: Authenticate and log in the user
        response = await backend.login(strategy, user)
        await user_manager.on_after_login(user, request, response)
        return response


    return router


def get_oauth_associate_router(
    oauth_client: BaseOAuth2,
    authenticator: Authenticator[models.UP, models.ID],
    get_user_manager: UserManagerDependency[models.UP, models.ID],
    user_schema: Type[schemas.U],
    state_secret: SecretType,
    redirect_url: Optional[str] = None,
    requires_verification: bool = False,
) -> APIRouter:
    """Generate a router with the OAuth routes to associate an authenticated user."""
    router = APIRouter()

    get_current_active_user = authenticator.current_user(
        active=True, verified=requires_verification
    )

    callback_route_name = f"oauth-associate:{oauth_client.name}.callback"

    if redirect_url is not None:
        oauth2_authorize_callback = OAuth2AuthorizeCallback(
            oauth_client,
            redirect_url=redirect_url,
        )
    else:
        oauth2_authorize_callback = OAuth2AuthorizeCallback(
            oauth_client,
            route_name=callback_route_name,
        )

    @router.get(
        "/authorize",
        name=f"oauth-associate:{oauth_client.name}.authorize",
        response_model=OAuth2AuthorizeResponse,
    )
    async def authorize(
        request: Request,
        scopes: List[str] = Query(None),
        user: models.UP = Depends(get_current_active_user),
    ) -> OAuth2AuthorizeResponse:
        if redirect_url is not None:
            authorize_redirect_url = redirect_url
        else:
            authorize_redirect_url = str(request.url_for(callback_route_name))

        state_data: Dict[str, str] = {"sub": str(user.id)}
        state = generate_state_token(state_data, state_secret)
        authorization_url = await oauth_client.get_authorization_url(
            authorize_redirect_url,
            state,
            scopes,
        )

        return OAuth2AuthorizeResponse(authorization_url=authorization_url)

    @router.get(
        "/callback",
        response_model=user_schema,
        name=callback_route_name,
        description="The response varies based on the authentication backend used.",
        responses={
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            "INVALID_STATE_TOKEN": {
                                "summary": "Invalid state token.",
                                "value": None,
                            },
                        }
                    }
                },
            },
        },
    )
    async def callback(
        request: Request,
        user: models.UP = Depends(get_current_active_user),
        access_token_state: Tuple[OAuth2Token, str] = Depends(
            oauth2_authorize_callback
        ),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ):
        token, state = access_token_state
        account_id, account_email = await oauth_client.get_id_email(
            token["access_token"]
        )

        if account_email is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.OAUTH_NOT_AVAILABLE_EMAIL,
            )

        try:
            state_data = decode_jwt(state, state_secret, [STATE_TOKEN_AUDIENCE])
        except jwt.DecodeError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        if state_data["sub"] != str(user.id):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        user = await user_manager.oauth_associate_callback(
            user,
            oauth_client.name,
            token["access_token"],
            account_id,
            account_email,
            token.get("expires_at"),
            token.get("refresh_token"),
            request,
        )

        return schemas.model_validate(user_schema, user)

    # @router.post(
    #     "/login",
    #     response_model=user_schema,
    #     name=f"oauth-associate:{oauth_client.name}.login",
    #     description="Login a user with an id_token shared from the frontend.",
    #     responses={
    #         status.HTTP_400_BAD_REQUEST: {
    #             "model": ErrorModel,
    #             "content": {
    #                 "application/json": {
    #                     "examples": {
    #                         "INVALID_ID_TOKEN": {
    #                             "summary": "Invalid ID token.",
    #                             "value": {"detail": "Invalid ID token."},
    #                         },
    #                     }
    #                 }
    #             },
    #         },
    #     },
    # )
    # async def login(
    #     request: Request,
    #     id_token: str,
    #     user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    #     strategy: Strategy[models.UP, models.ID] = Depends(backend.get_strategy),
    # ):
    #     try:
    #         token = OAuth2Token(access_token=id_token)
    #         account_id, account_email = await oauth_client.get_id_email(token.access_token)
    #     except Exception:
    #         raise HTTPException(
    #             status_code=status.HTTP_400_BAD_REQUEST,
    #             detail="Invalid ID token.",
    #         )

    #     if account_email is None:
    #         raise HTTPException(
    #             status_code=status.HTTP_400_BAD_REQUEST,
    #             detail=ErrorCode.OAUTH_NOT_AVAILABLE_EMAIL,
    #         )

    #     try:
    #         user = await user_manager.oauth_callback(
    #             oauth_client.name,
    #             id_token,
    #             account_id,
    #             account_email,
    #             None,
    #             None,
    #             request,
    #             associate_by_email=associate_by_email,
    #             is_verified_by_default=is_verified_by_default,
    #         )
    #     except UserAlreadyExists:
    #         raise HTTPException(
    #             status_code=status.HTTP_400_BAD_REQUEST,
    #             detail=ErrorCode.OAUTH_USER_ALREADY_EXISTS,
    #         )

    #     if not user.is_active:
    #         raise HTTPException(
    #             status_code=status.HTTP_400_BAD_REQUEST,
    #             detail=ErrorCode.LOGIN_BAD_CREDENTIALS,
    #         )

    #     # Authenticate
    #     response = await backend.login(strategy, user)
    #     await user_manager.on_after_login(user, request, response)
    #     return response

    return router
