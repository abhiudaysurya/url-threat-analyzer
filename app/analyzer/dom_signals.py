"""DOM signal extraction module"""
import re
from typing import List
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract
import structlog
from app.schemas import AnalysisResult

logger = structlog.get_logger(__name__)

# Top brands for impersonation detection (same list as static analysis)
TOP_BRANDS = [
    "google", "facebook", "paypal", "amazon", "apple",
    "microsoft", "netflix", "instagram", "twitter", "linkedin",
    "dropbox", "chase", "wellsfargo", "bankofamerica", "gmail",
    "outlook", "yahoo", "steam", "coinbase", "binance"
]

# Urgency phrases
URGENCY_PHRASES = [
    "act now", "verify immediately", "your account will be suspended",
    "click here to confirm", "urgent action required", "verify your account",
    "confirm your identity", "suspended account", "unusual activity",
    "security alert", "immediate action", "limited time"
]


class DOMAnalyzer:
    """Analyzes HTML DOM for phishing signals"""

    def analyze(self, html: str | None, base_url: str) -> AnalysisResult:
        """
        Extract DOM-based signals from HTML content.

        Args:
            html: HTML content to analyze
            base_url: Base URL of the page

        Returns:
            AnalysisResult with score and reasons
        """
        if not html:
            return AnalysisResult(score=0.0, reasons=["No HTML content to analyze"])

        soup = BeautifulSoup(html, 'html.parser')
        reasons = []
        weights = []

        base_domain = self._extract_domain(base_url)

        # Check 1: Password inputs
        password_weight = self._check_password_inputs(soup, reasons)
        if password_weight > 0:
            weights.append(password_weight)

        # Check 2: External form actions
        form_weight = self._check_external_forms(soup, base_domain, reasons)
        if form_weight > 0:
            weights.append(form_weight)

        # Check 3: External scripts
        script_weight = self._check_external_scripts(soup, base_domain, reasons)
        if script_weight > 0:
            weights.append(script_weight)

        # Check 4: Iframes
        iframe_weight = self._check_iframes(soup, reasons)
        if iframe_weight > 0:
            weights.append(iframe_weight)

        # Check 5: Hidden elements
        hidden_weight = self._check_hidden_elements(soup, reasons)
        if hidden_weight > 0:
            weights.append(hidden_weight)

        # Check 6: Obfuscated JavaScript
        obfuscation_weight = self._check_obfuscated_js(soup, reasons)
        if obfuscation_weight > 0:
            weights.append(obfuscation_weight)

        # Check 7: Brand impersonation
        brand_weight = self._check_brand_impersonation(soup, base_domain, reasons)
        if brand_weight > 0:
            weights.append(brand_weight)

        # Check 8: Favicon domain mismatch
        favicon_weight = self._check_favicon_mismatch(soup, base_domain, reasons)
        if favicon_weight > 0:
            weights.append(favicon_weight)

        # Check 9: Urgency language
        urgency_weight = self._check_urgency_language(soup, reasons)
        if urgency_weight > 0:
            weights.append(urgency_weight)

        # Check 10: Data URI scripts
        data_uri_weight = self._check_data_uri_scripts(soup, reasons)
        if data_uri_weight > 0:
            weights.append(data_uri_weight)

        # Calculate final score
        score = sum(weights) / len(weights) if weights else 0.0
        score = min(score, 1.0)

        return AnalysisResult(score=score, reasons=reasons)

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract registered domain from URL"""
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}".lower()

    def _check_password_inputs(self, soup: BeautifulSoup, reasons: List[str]) -> float:
        """Check for password input fields"""
        password_inputs = soup.find_all('input', {'type': 'password'})

        if password_inputs:
            count = len(password_inputs)
            reasons.append(f"Contains {count} password input field(s)")
            return 0.6

        return 0.0

    def _check_external_forms(
        self, soup: BeautifulSoup, base_domain: str, reasons: List[str]
    ) -> float:
        """Check for forms submitting to external domains"""
        forms = soup.find_all('form')
        external_count = 0

        for form in forms:
            action = form.get('action', '')
            if action and action.startswith('http'):
                action_domain = self._extract_domain(action)
                if action_domain and action_domain != base_domain:
                    external_count += 1

        if external_count > 0:
            reasons.append(f"{external_count} form(s) submit to external domain")
            return 0.75

        return 0.0

    def _check_external_scripts(
        self, soup: BeautifulSoup, base_domain: str, reasons: List[str]
    ) -> float:
        """Check for external script sources"""
        scripts = soup.find_all('script', src=True)
        external_count = 0

        for script in scripts:
            src = script.get('src', '')
            if src.startswith('http'):
                src_domain = self._extract_domain(src)
                if src_domain and src_domain != base_domain:
                    external_count += 1

        if external_count > 0:
            reasons.append(f"{external_count} external script(s) loaded")
            # Cap at 0.9
            weight = min(0.3 * external_count, 0.9)
            return weight

        return 0.0

    def _check_iframes(self, soup: BeautifulSoup, reasons: List[str]) -> float:
        """Check for iframe elements"""
        iframes = soup.find_all('iframe')

        if iframes:
            count = len(iframes)
            reasons.append(f"Contains {count} iframe(s)")
            return 0.4

        return 0.0

    def _check_hidden_elements(self, soup: BeautifulSoup, reasons: List[str]) -> float:
        """Check for hidden elements"""
        all_elements = soup.find_all()
        total_count = len(all_elements)

        if total_count == 0:
            return 0.0

        hidden_count = 0

        for element in all_elements:
            style = element.get('style', '')
            if 'display:none' in style.replace(' ', '') or \
               'visibility:hidden' in style.replace(' ', ''):
                hidden_count += 1

        ratio = hidden_count / total_count

        if ratio > 0.1:
            reasons.append(f"High ratio of hidden elements ({ratio:.1%})")
            return 0.3

        return 0.0

    def _check_obfuscated_js(self, soup: BeautifulSoup, reasons: List[str]) -> float:
        """Check for obfuscated JavaScript"""
        scripts = soup.find_all('script')
        obfuscation_patterns = [
            r'\beval\s*\(',
            r'\bunescape\s*\(',
            r'\batob\s*\(',
            r'String\.fromCharCode\s*\('
        ]

        for script in scripts:
            script_text = script.string or ''
            for pattern in obfuscation_patterns:
                if re.search(pattern, script_text):
                    reasons.append("Obfuscated JavaScript detected (eval/unescape/atob)")
                    return 0.65

        return 0.0

    def _check_brand_impersonation(
        self, soup: BeautifulSoup, base_domain: str, reasons: List[str]
    ) -> float:
        """Check for brand impersonation in title and meta tags"""
        # Get title
        title = soup.find('title')
        title_text = title.string.lower() if title and title.string else ''

        # Get meta descriptions
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        desc_text = meta_desc.get('content', '').lower() if meta_desc else ''

        # Combine text
        text_to_check = f"{title_text} {desc_text}"

        for brand in TOP_BRANDS:
            if brand in text_to_check:
                # Brand name found in page, check if domain matches
                if brand not in base_domain:
                    reasons.append(f"Brand impersonation: '{brand}' in page but not in domain")
                    return 0.8

        return 0.0

    def _check_favicon_mismatch(
        self, soup: BeautifulSoup, base_domain: str, reasons: List[str]
    ) -> float:
        """Check if favicon is loaded from different domain"""
        favicon = soup.find('link', rel=re.compile(r'icon', re.I))

        if favicon:
            href = favicon.get('href', '')
            if href.startswith('http'):
                favicon_domain = self._extract_domain(href)
                if favicon_domain and favicon_domain != base_domain:
                    reasons.append("Favicon loaded from different domain")
                    return 0.45

        return 0.0

    def _check_urgency_language(self, soup: BeautifulSoup, reasons: List[str]) -> float:
        """Check for urgency/pressure language"""
        page_text = soup.get_text().lower()
        found_phrases = []

        for phrase in URGENCY_PHRASES:
            if phrase in page_text:
                found_phrases.append(phrase)

        if found_phrases:
            reasons.append(f"Urgency language detected: {', '.join(found_phrases[:3])}")
            return 0.5

        return 0.0

    def _check_data_uri_scripts(self, soup: BeautifulSoup, reasons: List[str]) -> float:
        """Check for data URI scripts"""
        scripts = soup.find_all('script', src=True)

        for script in scripts:
            src = script.get('src', '')
            if src.startswith('data:'):
                reasons.append("Script loaded via data URI")
                return 0.7

        return 0.0
