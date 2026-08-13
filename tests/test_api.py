"""API endpoint tests"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock
from app.main import app
from app.schemas import VerdictResponse

client = TestClient(app)


@pytest.fixture
def mock_cache():
    """Mock Redis cache"""
    with patch('app.api.routes.cache') as mock:
        mock.get_cached = AsyncMock(return_value=None)
        mock.set_cached = AsyncMock()
        mock.is_healthy = AsyncMock(return_value=True)
        yield mock


@pytest.fixture
def mock_analyze_url():
    """Mock analyze_url function"""
    with patch('app.api.routes.analyze_url') as mock:
        yield mock


def test_health_endpoint():
    """Test health check endpoint"""
    with patch('app.api.routes.cache.is_healthy', new_callable=AsyncMock) as mock_health:
        mock_health.return_value = True

        with patch('app.api.routes.threat_model') as mock_model:
            mock_model.model_loaded = True

            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()

            assert data["status"] == "ok"
            assert data["redis"] is True
            assert data["model_loaded"] is True


def test_analyze_safe_url(mock_cache, mock_analyze_url):
    """Test analysis of a known-safe URL (google.com)"""
    # Mock the analysis result
    mock_result = VerdictResponse(
        url="https://google.com",
        verdict="safe",
        confidence=0.1,
        reasons=[],
        cached=False,
        analysis_time_ms=1500
    )

    mock_analyze_url.return_value = mock_result

    # Make request
    response = client.post(
        "/analyze-url",
        json={"url": "https://google.com"}
    )

    assert response.status_code == 200
    data = response.json()

    assert data["url"] == "https://google.com"
    assert data["verdict"] == "safe"
    assert data["confidence"] <= 0.5
    assert isinstance(data["reasons"], list)
    assert data["cached"] is False
    assert data["analysis_time_ms"] > 0


def test_analyze_suspicious_url(mock_cache, mock_analyze_url):
    """Test analysis of a suspicious URL"""
    # Mock the analysis result
    mock_result = VerdictResponse(
        url="http://fake-paypal.tk/login",
        verdict="malicious",
        confidence=0.92,
        reasons=[
            "High-risk TLD: .tk",
            "Possible typosquatting of 'paypal' (distance: 1)",
            "Suspicious keywords in URL: login",
            "Brand impersonation: 'paypal' in page but not in domain"
        ],
        cached=False,
        analysis_time_ms=3200
    )

    mock_analyze_url.return_value = mock_result

    # Make request
    response = client.post(
        "/analyze-url",
        json={"url": "http://fake-paypal.tk/login"}
    )

    assert response.status_code == 200
    data = response.json()

    assert data["url"] == "http://fake-paypal.tk/login"
    assert data["verdict"] == "malicious"
    assert data["confidence"] >= 0.75
    assert len(data["reasons"]) > 0
    assert any("tk" in reason.lower() for reason in data["reasons"])


def test_analyze_invalid_url(mock_cache):
    """Test analysis with invalid URL"""
    response = client.post(
        "/analyze-url",
        json={"url": "not-a-valid-url"}
    )

    assert response.status_code == 400
    assert "detail" in response.json()


def test_analyze_missing_url():
    """Test analysis with missing URL field"""
    response = client.post(
        "/analyze-url",
        json={}
    )

    assert response.status_code == 422  # Validation error


def test_analyze_cached_result(mock_cache, mock_analyze_url):
    """Test that cached results are returned"""
    # Mock cached result
    cached_data = {
        "url": "https://example.com",
        "verdict": "safe",
        "confidence": 0.2,
        "reasons": [],
        "cached": False,
        "analysis_time_ms": 1000
    }

    mock_cache.get_cached.return_value = cached_data

    response = client.post(
        "/analyze-url",
        json={"url": "https://example.com"}
    )

    assert response.status_code == 200
    data = response.json()

    assert data["cached"] is True
    # analyze_url should not be called when cache hit
    mock_analyze_url.assert_not_called()


def test_rate_limiting():
    """Test rate limiting (requires actual requests)"""
    # This test would need to make actual requests to test rate limiting
    # For now, just verify the endpoint exists
    response = client.post(
        "/analyze-url",
        json={"url": "https://google.com"}
    )

    # Should not return 429 on first request
    assert response.status_code != 429


def test_health_redis_down():
    """Test health endpoint when Redis is down"""
    with patch('app.api.routes.cache.is_healthy', new_callable=AsyncMock) as mock_health:
        mock_health.return_value = False

        with patch('app.api.routes.threat_model') as mock_model:
            mock_model.model_loaded = True

            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()

            assert data["status"] == "degraded"
            assert data["redis"] is False


def test_analyze_empty_url(mock_cache):
    """Test analysis with empty URL"""
    response = client.post(
        "/analyze-url",
        json={"url": ""}
    )

    assert response.status_code == 400


def test_analyze_url_too_long(mock_cache):
    """Test analysis with URL exceeding max length"""
    long_url = "https://example.com/" + "a" * 3000

    response = client.post(
        "/analyze-url",
        json={"url": long_url}
    )

    assert response.status_code == 400
