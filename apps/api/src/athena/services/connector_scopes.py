from sqlalchemy.orm import Session

from athena.models import ConnectorScopeBinding, ConnectorScopeRevocation
from athena.tenant_queries import tenant_select


class ConnectorScopeError(RuntimeError):
    pass


class ConnectorScopeRegistry:
    def __init__(self, session: Session) -> None:
        self.session = session

    def require_approved(self, connector: str, scope: str) -> ConnectorScopeBinding:
        normalized_connector = connector.strip().lower()
        normalized_scope = scope.strip().lower()
        if not normalized_connector or not normalized_scope:
            raise ConnectorScopeError("Connector and provider scope are required")
        statement = tenant_select(
            self.session,
            ConnectorScopeBinding,
            ConnectorScopeBinding.connector == normalized_connector,
            ConnectorScopeBinding.scope == normalized_scope,
        )
        binding = self.session.scalar(statement)
        if binding is None:
            raise ConnectorScopeError(
                f"Provider scope {normalized_connector}:{normalized_scope} is not approved "
                "for this tenant"
            )
        revocation = self.session.scalar(
            tenant_select(
                self.session,
                ConnectorScopeRevocation,
                ConnectorScopeRevocation.binding_id == binding.id,
            )
        )
        if revocation is not None:
            raise ConnectorScopeError(
                f"Provider scope {normalized_connector}:{normalized_scope} approval is revoked"
            )
        return binding
