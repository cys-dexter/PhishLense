from typing import Dict, List
from fastapi import APIRouter, HTTPException, status
from app.core.analyzer import UrlAnalyzer
from app.core.config import settings
from app.models.schemas import SampleUrlItem, UrlAnalysisRequest, UrlAnalysisResponse

router = APIRouter(prefix="/api/v1", tags=["Inspection"])
analyzer = UrlAnalyzer()


@router.post("/analyze", response_model=UrlAnalysisResponse, status_code=status.HTTP_200_OK)
def analyze_url(payload: UrlAnalysisRequest) -> UrlAnalysisResponse:
    target_url = payload.url.strip()
    if not target_url:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Target URL must not be empty.",
        )
    try:
        return analyzer.analyze(target_url)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis engine error: {str(exc)}",
        )


@router.get("/samples", response_model=List[SampleUrlItem], status_code=status.HTTP_200_OK)
def get_sample_urls() -> List[SampleUrlItem]:
    return [
        SampleUrlItem(
            label="Legitimate Repository",
            url="https://github.com/cys-dexter/PhishLense",
            expected_risk="SAFE",
            description="Authentic project repository on trusted domain.",
        ),
        SampleUrlItem(
            label="Brand Spoofing & Cheap TLD",
            url="http://paypal.com.account-update.notice-security.xyz/login/verify.php",
            expected_risk="DANGEROUS",
            description="PayPal brand spoofed in subdomain with .xyz abuse TLD.",
        ),
        SampleUrlItem(
            label="Direct IP Host & Non-Standard Port",
            url="http://192.168.1.250:8443/chase/banking/signin",
            expected_risk="DANGEROUS",
            description="Numerical host using non-standard port and credential traps.",
        ),
        SampleUrlItem(
            label="Punycode Homoglyph Spoof",
            url="https://xn--pple-43d.com/id/verify-account",
            expected_risk="DANGEROUS",
            description="Punycode representation mimicking Apple domain characters.",
        ),
        SampleUrlItem(
            label="URL Shortener Masking",
            url="https://bit.ly/secure-banking-portal-update",
            expected_risk="SUSPICIOUS",
            description="Shortened URL hiding true destination server.",
        ),
        SampleUrlItem(
            label="Userinfo @ Redirect Exploit",
            url="http://amazon.com@update-profile-gateway.click/login",
            expected_risk="DANGEROUS",
            description="Uses '@' to deceive user before redirecting to rogue click TLD.",
        ),
    ]


@router.get("/health", response_model=Dict[str, str], status_code=status.HTTP_200_OK)
def get_health() -> Dict[str, str]:
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "creator": settings.AUTHOR_NAME,
        "github": settings.GITHUB_USERNAME,
        "repository": settings.REPOSITORY_NAME,
    }
