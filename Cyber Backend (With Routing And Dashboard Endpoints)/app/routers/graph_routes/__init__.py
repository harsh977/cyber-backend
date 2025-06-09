from .cvss_scores_per_ip import router as cvss_scores_per_ip_router
from .exploit_availability import router as exploit_availability_router
from .high_severity_yearwise_summary import router as high_severity_yearwise_summary_router
from .patch_availability import router as patch_availability_router
from .protocol_distribution import router as protocol_distribution_router
from .risk_factor_distribution import router as risk_factor_distribution_router
from .severity_counts import router as severity_counts_router
from .top_vulnerabilities import router as top_vulnerabilities_router
from .vulnerabilities_by_ip import router as vulnerabilities_by_ip_router
from .vulnerabilities_by_port import router as vulnerabilities_by_port_router
from .vulnerability_trend import router as vulnerability_trend_router





routers = [
    cvss_scores_per_ip_router,
    exploit_availability_router,
    high_severity_yearwise_summary_router,
    patch_availability_router,
    protocol_distribution_router,
    risk_factor_distribution_router,
    severity_counts_router,
    top_vulnerabilities_router,
    vulnerabilities_by_ip_router,
    vulnerabilities_by_port_router,
    vulnerability_trend_router
]