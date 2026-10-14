from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW_RISK = "LOW RISK"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS = "DANGEROUS"


class UrlAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)


class UrlComponents(BaseModel):
    raw_url: str
    normalized_url: str
    scheme: str
    netloc: str
    hostname: str
    subdomain: str
    domain: str
    registered_domain: str
    tld: str
    port: Optional[str] = None
    path: str
    query: str
    fragment: str
    query_params: Dict[str, List[str]]
    is_ip_address: bool


class FindingDetail(BaseModel):
    rule_id: str
    title: str
    category: str
    severity: SeverityLevel
    score_impact: int
    plain_english_explanation: str
    technical_detail: str


class SeverityCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    info: int


class UrlAnalysisResponse(BaseModel):
    url: str
    normalized_url: str
    risk_score: int
    risk_level: RiskLevel
    verdict_summary: str
    components: UrlComponents
    severity_counts: SeverityCounts
    findings: List[FindingDetail]
    recommendations: List[str]
    scan_timestamp: str


class SampleUrlItem(BaseModel):
    label: str
    url: str
    expected_risk: str
    description: str
