"""Main FastAPI application"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
import logging
import structlog
from app.api.routes import router
from app.core.cache import cache
from app.core.limiter import limiter
from app.core.config import settings

# Configure structured logging
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.make_filtering_bound_logger(
        getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    ),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events.

    Handles:
    - Redis connection initialization on startup
    - Redis connection cleanup on shutdown
    """
    # Startup
    logger.info("application_starting")

    try:
        await cache.connect()
        logger.info("startup_complete")
    except Exception as e:
        logger.error("startup_failed", error=str(e))

    yield

    # Shutdown
    logger.info("application_shutting_down")

    try:
        await cache.close()
        logger.info("shutdown_complete")
    except Exception as e:
        logger.error("shutdown_failed", error=str(e))


# Create FastAPI app
app = FastAPI(
    title="URL Threat Analysis API",
    description="Production-ready API for analyzing URLs for phishing and malicious content",
    version="1.0.0",
    lifespan=lifespan
)

# Register rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Include routes
app.include_router(router)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler to catch any unhandled exceptions.

    Args:
        request: FastAPI request
        exc: Exception that was raised

    Returns:
        JSON response with error details
    """
    logger.error(
        "unhandled_exception",
        path=request.url.path,
        method=request.method,
        error=str(exc),
        exc_info=True
    )

    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "error": str(exc)
        }
    )


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    Middleware to log all HTTP requests.

    Args:
        request: FastAPI request
        call_next: Next middleware/handler

    Returns:
        Response from the next handler
    """
    logger.info(
        "request_received",
        method=request.method,
        path=request.url.path,
        client_ip=request.client.host
    )

    response = await call_next(request)

    logger.info(
        "request_completed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code
    )

    return response
