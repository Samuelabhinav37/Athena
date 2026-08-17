from fastapi import APIRouter

from athena.auth import ViewerPrincipal
from athena.schemas import AuthenticatedPrincipalResponse

router = APIRouter(prefix="/v1/auth", tags=["authentication"])


@router.get("/me", response_model=AuthenticatedPrincipalResponse)
def current_principal(principal: ViewerPrincipal) -> AuthenticatedPrincipalResponse:
    return AuthenticatedPrincipalResponse(
        subject=principal.subject,
        username=principal.username,
        roles=sorted(principal.roles),
    )
