from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from app.models.api_endpoint import ApiEndpoint
from app.services.dast_http_client import DastAuthContext, DastHttpClient
from app.services.dast_probes import DastProbeResult, DastVerificationStatus, DastProbeType


class BaseVulnerabilityVerifier(ABC):
    """
    Abstract Base Class for pluggable Kyptic Vulnerability Verifiers.
    All dynamic targeted verifiers must implement this common interface.
    """

    @property
    @abstractmethod
    def vulnerability_id(self) -> str:
        """Unique identifier matching VulnerabilityRegistry vulnerability_id."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable display name."""
        pass

    @property
    def supported_execution_modes(self) -> List[str]:
        return ["TARGETED_VERIFICATION", "DYNAMIC_PROBE"]

    @abstractmethod
    def verify(
        self,
        endpoint: ApiEndpoint,
        client: DastHttpClient,
        base_url: str,
        auth_context: DastAuthContext,
        params: Optional[Dict[str, Any]] = None,
    ) -> DastProbeResult:
        """
        Executes a deterministic, safe, single-hypothesis verification test.
        Must return a structured DastProbeResult with status:
        VERIFIED_VULNERABLE (CONFIRMED), VERIFIED_SECURE (NOT_CONFIRMED), or INCONCLUSIVE.
        """
        pass
