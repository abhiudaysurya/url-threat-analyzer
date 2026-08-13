"""API routes for URL threat analysis"""
import hashlib
from fastapi import APIRouter, Request, HTTPException
from slowapi import Limiter
from slowapi.util import get_remote_address
import structlog
from app.schemas import AnalyzeURLRequest, VerdictResponse, HealthResponse
from app.analyzer.orchestrator import analyze_url
from app.core.cache import cache
from app.core.limiter import limiter
from app.core.config import settings
from app.ml.model import threat_model

logger = structlog.get_logger(__name__)

router = APIRouter()


def normalize_url(url: str) -> str:
    """Normalize URL for caching"""
    # Remove trailing slashes, convert to lowercase
    url = url.strip().lower()
    if url.endswith('/'):
        url = url[:-1]
    return url


def hash_url(url: str) -> str:
    """Generate SHA256 hash of URL"""
    return hashlib.sha256(url.encode()).hexdigest()


@router.post("/analyze-url", response_model=VerdictResponse)
@limiter.limit(settings.RATE_LIMIT)
async def analyze_url_endpoint(
    request: Request,
    body: AnalyzeURLRequest
) -> VerdictResponse:
    """
    Analyze a URL for threat indicators.

    This endpoint performs comprehensive analysis including
    - Static URL analysis (domain age, typosquatting, etc.)
    - Content scraping with SSRF protection
    - DOM signal extraction
    - Machine learning classification

    Rate limited to 10 requests per minute per IP.

    Args:
        request: FastAPI request object
        body: Request body with URL

    Returns:
        VerdictResponse with verdict, confidence, and reasons

    Raises:
        HTTPException: If URL validation fails or analysis error occurs
    """
    url = body.url
    normalized_url = normalize_url(url)
    url_hash = hash_url(normalized_url)


    # Check cache first
    cached_result = await cache.get_cached(url_hash)
    if cached_result:
        logger.info("cache_hit", url_hash=url_hash)
        cached_result['cached'] = True
        return VerdictResponse(**cached_result)

    # Run analysis
    try:
        result = await analyze_url(normalized_url)

        # Cache the result
        result_dict = result.model_dump()
        await cache.set_cached(url_hash, result_dict)

        return result

    except ValueError as e:
        # URL validation error
        logger.warning("validation_error", url_hash=url_hash, error=str(e))
        raise HTTPException(status_code=400, detail=str(e))

    except Exception as e:
        # Unexpected error
        logger.error("analysis_error", url_hash=url_hash, error=str(e), exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Internal server error during analysis"
        )


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """
    Health check endpoint.

    Returns:
        HealthResponse with system status
    """
    redis_healthy = await cache.is_healthy()
    model_loaded = threat_model.model_loaded

    status = "ok" if redis_healthy else "degraded"

    logger.info(
        "health_check",
        status=status,
        redis=redis_healthy,
        model_loaded=model_loaded
    )

    return HealthResponse(
        status=status,
        redis=redis_healthy,
        model_loaded=model_loaded
    )
