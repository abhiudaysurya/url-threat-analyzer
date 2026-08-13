"""Unit tests for static URL analysis"""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from app.analyzer.static import StaticAnalyzer


@pytest.fixture
def analyzer():
    """Create StaticAnalyzer instance"""
    return StaticAnalyzer()


def test_check_domain_age_new_domain(analyzer):
    """Test detection of newly registered domain"""
    reasons = []

    # Mock whois to return recent creation date
    with patch('app.analyzer.static.whois.whois') as mock_whois:
        mock_whois_result = MagicMock()
        mock_whois_result.creation_date = datetime.now() - timedelta(days=15)
        mock_whois.return_value = mock_whois_result

        weight = analyzer._check_domain_age("newdomain.com", reasons)

        assert weight == 0.7
        assert len(reasons) == 1
        assert "15 days ago" in reasons[0]


def test_check_domain_age_old_domain(analyzer):
    """Test that old domains don't trigger warning"""
    reasons = []

    with patch('app.analyzer.static.whois.whois') as mock_whois:
        mock_whois_result = MagicMock()
        mock_whois_result.creation_date = datetime.now() - timedelta(days=365)
        mock_whois.return_value = mock_whois_result

        weight = analyzer._check_domain_age("olddomain.com", reasons)

        assert weight == 0.0
        assert len(reasons) == 0


def test_check_url_entropy_high(analyzer):
    """Test detection of high entropy hostname"""
    reasons = []

    # Random-looking hostname should have high entropy
    weight = analyzer._check_url_entropy("xk7dn2p9qw3m.com", reasons)

    assert weight == 0.5
    assert len(reasons) == 1
    assert "entropy" in reasons[0].lower()


def test_check_url_entropy_low(analyzer):
    """Test that normal hostnames don't trigger warning"""
    reasons = []

    weight = analyzer._check_url_entropy("google.com", reasons)

    assert weight == 0.0
    assert len(reasons) == 0


def test_check_subdomain_depth_excessive(analyzer):
    """Test detection of excessive subdomain depth"""
    reasons = []

    weight = analyzer._check_subdomain_depth("a.b.c.d.e", reasons)

    assert weight == 0.4
    assert len(reasons) == 1
    assert "subdomain" in reasons[0].lower()


def test_check_subdomain_depth_normal(analyzer):
    """Test that normal subdomain depth is OK"""
    reasons = []

    weight = analyzer._check_subdomain_depth("www", reasons)

    assert weight == 0.0
    assert len(reasons) == 0


def test_check_ip_hostname_ipv4(analyzer):
    """Test detection of IPv4 address as hostname"""
    reasons = []

    weight = analyzer._check_ip_hostname("192.168.1.1", reasons)

    assert weight == 0.8
    assert len(reasons) == 1
    assert "IP address" in reasons[0]


def test_check_ip_hostname_domain(analyzer):
    """Test that regular domain names are OK"""
    reasons = []

    weight = analyzer._check_ip_hostname("example.com", reasons)

    assert weight == 0.0
    assert len(reasons) == 0


def test_check_typosquatting_detected(analyzer):
    """Test detection of typosquatting"""
    reasons = []

    # "gogle" is distance 1 from "google"
    weight = analyzer._check_typosquatting("gogle", reasons)

    assert weight == 0.75
    assert len(reasons) == 1
    assert "typosquatting" in reasons[0].lower()
    assert "google" in reasons[0].lower()


def test_check_typosquatting_not_detected(analyzer):
    """Test that legitimate domains are not flagged"""
    reasons = []

    weight = analyzer._check_typosquatting("example", reasons)

    assert weight == 0.0
    assert len(reasons) == 0


def test_check_suspicious_keywords_found(analyzer):
    """Test detection of suspicious keywords"""
    reasons = []

    weight = analyzer._check_suspicious_keywords(
        "https://example.com/login/verify-account",
        reasons
    )

    assert weight == 0.5
    assert len(reasons) == 1
    assert "login" in reasons[0].lower()
    assert "verify" in reasons[0].lower()


def test_check_suspicious_keywords_not_found(analyzer):
    """Test that normal URLs don't trigger keywords"""
    reasons = []

    weight = analyzer._check_suspicious_keywords(
        "https://example.com/about",
        reasons
    )

    assert weight == 0.0
    assert len(reasons) == 0


def test_check_high_risk_tld_detected(analyzer):
    """Test detection of high-risk TLD"""
    reasons = []

    weight = analyzer._check_high_risk_tld("tk", reasons)

    assert weight == 0.4
    assert len(reasons) == 1
    assert ".tk" in reasons[0]


def test_check_high_risk_tld_safe(analyzer):
    """Test that safe TLDs are not flagged"""
    reasons = []

    weight = analyzer._check_high_risk_tld("com", reasons)

    assert weight == 0.0
    assert len(reasons) == 0


def test_check_url_length_excessive(analyzer):
    """Test detection of excessive URL length"""
    reasons = []

    long_url = "https://example.com/" + "a" * 200
    weight = analyzer._check_url_length(long_url, reasons)

    assert weight == 0.3
    assert len(reasons) == 1
    assert "length" in reasons[0].lower()


def test_check_url_length_normal(analyzer):
    """Test that normal URL length is OK"""
    reasons = []

    weight = analyzer._check_url_length("https://example.com/page", reasons)

    assert weight == 0.0
    assert len(reasons) == 0


def test_check_redirects_excessive(analyzer):
    """Test detection of excessive redirects"""
    reasons = []

    # Mock httpx to simulate redirects
    with patch('app.analyzer.static.httpx.Client') as mock_client:
        mock_response = MagicMock()
        mock_response.history = [MagicMock()] * 5  # 5 redirects
        mock_client.return_value.__enter__.return_value.head.return_value = mock_response

        weight = analyzer._check_redirects("https://example.com", reasons)

        assert weight == 0.4
        assert len(reasons) == 1
        assert "redirect" in reasons[0].lower()


def test_levenshtein_distance(analyzer):
    """Test Levenshtein distance calculation"""
    assert analyzer._levenshtein_distance("google", "gogle") == 1
    assert analyzer._levenshtein_distance("facebook", "faceboook") == 2
    assert analyzer._levenshtein_distance("test", "test") == 0
    assert analyzer._levenshtein_distance("abc", "xyz") == 3


def test_calculate_entropy(analyzer):
    """Test entropy calculation"""
    # Uniform distribution should have high entropy
    entropy1 = analyzer._calculate_entropy("abcdefghij")

    # Repeated characters should have lower entropy
    entropy2 = analyzer._calculate_entropy("aaaaaaaaaa")

    assert entropy1 > entropy2
    assert entropy2 == 0.0  # All same character


def test_full_analysis(analyzer):
    """Test full analysis of a suspicious URL"""
    # URL with multiple red flags
    url = "http://gogle.tk/login-verify-account"

    result = analyzer.analyze(url)

    assert result.score > 0.0
    assert len(result.reasons) > 0
    assert isinstance(result.score, float)
    assert 0.0 <= result.score <= 1.0


def test_full_analysis_safe_url(analyzer):
    """Test full analysis of a safe URL"""
    url = "https://www.google.com"

    result = analyzer.analyze(url)

    # Should have low score (Google is legitimate)
    assert isinstance(result.score, float)
    assert 0.0 <= result.score <= 1.0
