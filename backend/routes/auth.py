"""
IRVES — Auth Route
Handles OAuth2 flows for GitHub and GitLab integrations.
"""

import logging
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Request, HTTPException
from starlette.responses import RedirectResponse

from config import settings
from services.settings_service import settings_service

logger = logging.getLogger(__name__)

router = APIRouter()

oauth = OAuth()

# Configure GitHub
if settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET:
    oauth.register(
        name='github',
        client_id=settings.GITHUB_CLIENT_ID,
        client_secret=settings.GITHUB_CLIENT_SECRET,
        access_token_url='https://github.com/login/oauth/access_token',
        access_token_params=None,
        authorize_url='https://github.com/login/oauth/authorize',
        authorize_params=None,
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'repo,user'},
    )

# Configure GitLab
if settings.GITLAB_CLIENT_ID and settings.GITLAB_CLIENT_SECRET:
    oauth.register(
        name='gitlab',
        client_id=settings.GITLAB_CLIENT_ID,
        client_secret=settings.GITLAB_CLIENT_SECRET,
        access_token_url='https://gitlab.com/oauth/token',
        authorize_url='https://gitlab.com/oauth/authorize',
        api_base_url='https://gitlab.com/api/v4/',
        client_kwargs={'scope': 'api'},
    )

@router.get("/{provider}/login")
async def login(provider: str, request: Request):
    """Initiate OAuth flow."""
    client = oauth.create_client(provider)
    if not client:
        raise HTTPException(status_code=400, detail=f"Provider {provider} not configured globally for IRVES platform.")
    
    # We pass return_to state to redirect smoothly
    return_to = request.query_params.get("return_to", "/settings")
    request.session["auth_return_to"] = return_to
    
    redirect_uri = settings.REDIRECT_URI
    return await client.authorize_redirect(request, redirect_uri)

@router.get("/callback")
async def auth_callback(request: Request):
    """Handle OAuth callback and store tokens."""
    provider = "github"
    if "gitlab.com" in str(request.url): provider = "gitlab"
        
    client = oauth.create_client(provider)
    if not client:
         raise HTTPException(status_code=400, detail="Invalid provider in callback")

    try:
        token = await client.authorize_access_token(request)
        user_info = await client.get('user', token=token)
            
        user_data = user_info.json()
        username = user_data.get("login") or user_data.get("username")
        avatar = user_data.get("avatar_url")
        
        # Store securely in settings
        settings_service.update_section("integrations", {
            provider: {
                "connected": True,
                "access_token": token.get("access_token"),
                "username": username,
                "avatar": avatar,
                "provider": provider
            }
        })
        
        logger.info(f"Successfully connected {provider} account via OAuth: {username}")
        
        return_to = request.session.get("auth_return_to", "/settings")
        # Redirect back to where they came from
        return RedirectResponse(url=f"{return_to}?auth=success")
        
    except Exception as e:
        logger.error(f"Auth callback error: {e}")
        return RedirectResponse(url="/settings?auth=error")

@router.get("/{provider}/repos")
async def list_repos(provider: str):
    """List repositories for the connected account."""
    stored = settings_service.load()
    integ = stored.get("integrations", {}).get(provider, {})
    
    if not integ.get("connected") or not integ.get("access_token"):
        raise HTTPException(status_code=401, detail=f"{provider} not connected")
    
    import httpx
    token = integ["access_token"]
    
    try:
        if provider == "github":
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://api.github.com/user/repos",
                    headers={"Authorization": f"token {token}"},
                    params={"sort": "updated", "per_page": 100}
                )
                resp.raise_for_status()
                repos = resp.json()
                return [{
                    "id": r["id"],
                    "name": r["full_name"],
                    "url": r["clone_url"],
                    "description": r["description"],
                    "private": r["private"],
                    "stars": r["stargazers_count"],
                    "language": r["language"],
                    "default_branch": r.get("default_branch", "main")
                } for r in repos]
        
        elif provider == "gitlab":
             async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://gitlab.com/api/v4/projects",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"membership": "true", "simple": "true", "order_by": "updated_at"}
                )
                resp.raise_for_status()
                repos = resp.json()
                return [{
                    "id": r["id"],
                    "name": r["path_with_namespace"],
                    "url": r["http_url_to_repo"],
                    "description": r["description"],
                    "private": r["visibility"] == "private",
                    "stars": r["star_count"],
                    "language": None,
                    "default_branch": r.get("default_branch", "main")
                } for r in repos]
                
    except Exception as e:
        logger.error(f"Failed to fetch {provider} repos: {e}")
        raise HTTPException(status_code=500, detail=str(e))
