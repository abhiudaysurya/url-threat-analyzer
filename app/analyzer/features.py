"""Feature extraction for ML model"""
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
import tldextract
from tldextract.tldextract import ExtractResult
from datetime import datetime
import whois
import structlog
from app.analyzer.static import StaticAnalyzer, TOP_BRANDS
from app.schemas import ScrapeResult, AnalysisResult

logger = structlog.get_logger(__name__)

# TLD risk scores
TLD_RISK_SCORES = {
    ".xyz": 0.8, ".top": 0.8, ".tk": 0.9, ".ml": 0.9, ".ga": 0.9,
    ".cf": 0.9, ".gq": 0.9, ".pw": 0.7, ".click": 0.7, ".link": 0.7,
    ".com": 0.1, ".org": 0.2, ".net": 0.2, ".edu": 0.0, ".gov": 0.0
}


class FeatureExtractor:
    """Extracts numerical features for ML model"""

    def __init__(self):
        self.static_analyzer = StaticAnalyzer()

    def extract_features(
        self,
        url: str,
        static_result: AnalysisResult,
        dom_result: Optional[AnalysisResult],
        scrape_result: Optional[ScrapeResult],
        redirect_count: int = 0
    ) -> Dict[str, float]:
        """
        Extract all 32 features from URL and analysis results.

        Args:
            url: Original URL
            static_result: Result from static analysis
            dom_result: Result from DOM analysis (optional)
            scrape_result: Result from scraping (optional)
            redirect_count: Number of redirects

        Returns:
            Dictionary of feature name -> value
        """
        features = {}

        # Parse URL
        parsed = urlparse(url)
        ext = tldextract.extract(url)

        # URL features (13 features)
        features.update(self._extract_url_features(url, parsed, ext))

        # Domain features (3 features)
        features.update(self._extract_domain_features(ext))

        # Content features (14 features)
        features.update(self._extract_content_features(
            scrape_result, dom_result, redirect_count
        ))

        # Composite scores (3 features)
        features['static_score'] = static_result.score
        features['dom_score'] = dom_result.score if dom_result else 0.0

        # Google Safe Browsing flag (high priority feature)
        # Check if any reason mentions Google Safe Browsing
        has_gsb_threat = any('Google Safe Browsing' in reason or 'safe browsing' in reason.lower()
                            for reason in static_result.reasons)
        features['google_safe_browsing_threat'] = 1.0 if has_gsb_threat else 0.0

        return features

    def _extract_url_features(
        self, url: str, parsed: urlparse, ext: ExtractResult
    ) -> Dict[str, float]:
        """Extract URL-based features"""
        features = {}

        # Length features
        features['url_length'] = float(len(url))
        features['hostname_length'] = float(len(parsed.netloc))
        features['path_length'] = float(len(parsed.path))
        features['query_length'] = float(len(parsed.query))

        # Structure features
        subdomain_parts = ext.subdomain.split('.') if ext.subdomain else []
        features['subdomain_count'] = float(len(subdomain_parts))

        path_parts = [p for p in parsed.path.split('/') if p]
        features['path_depth'] = float(len(path_parts))

        query_params = parse_qs(parsed.query)
        features['query_param_count'] = float(len(query_params))

        # Entropy and character analysis
        hostname = parsed.netloc
        features['entropy_hostname'] = self._calculate_entropy(hostname)
        features['digit_ratio'] = self._calculate_digit_ratio(hostname)
        features['hyphen_count'] = float(hostname.count('-'))

        # Boolean features
        features['has_ip_hostname'] = float(self._is_ip_address(hostname))
        features['has_https'] = float(parsed.scheme == 'https')

        # Keyword count
        features['url_keyword_count'] = float(self._count_suspicious_keywords(url))

        # TLD risk score
        tld = f".{ext.suffix}" if ext.suffix else ".com"
        features['tld_risk_score'] = TLD_RISK_SCORES.get(tld, 0.3)

        return features

    def _extract_domain_features(self, ext: ExtractResult) -> Dict[str, float]:
        """Extract domain-based features"""
        features = {}

        domain = ext.registered_domain

        # Domain age
        age_days = self._get_domain_age_days(domain)
        features['domain_age_days'] = min(float(age_days), 3650.0) if age_days >= 0 else -1.0
        features['is_newly_registered'] = float(0 <= age_days < 30)

        # Typosquatting distance
        features['typosquat_min_distance'] = float(
            self._get_min_typosquat_distance(ext.domain)
        )

        return features

    def _extract_content_features(
        self,
        scrape_result: Optional[ScrapeResult],
        dom_result: Optional[AnalysisResult],
        redirect_count: int
    ) -> Dict[str, float]:
        """Extract content-based features"""
        features = {}

        if not scrape_result or not scrape_result.is_successful:
            # Default values when scraping failed
            features['has_password_form'] = 0.0
            features['external_form_count'] = 0.0
            features['external_script_count'] = 0.0
            features['iframe_count'] = 0.0
            features['hidden_element_ratio'] = 0.0
            features['has_obfuscated_js'] = 0.0
            features['has_brand_impersonation'] = 0.0
            features['redirect_count'] = float(redirect_count)
            features['requests_made_count'] = 0.0
            features['has_data_uri_script'] = 0.0
            features['urgency_phrase_count'] = 0.0
            features['favicon_mismatch'] = 0.0
            return features

        # Extract from DOM analysis reasons
        if dom_result and dom_result.reasons:
            reasons_text = ' '.join(dom_result.reasons).lower()

            features['has_password_form'] = float('password input' in reasons_text)
            features['has_obfuscated_js'] = float('obfuscated javascript' in reasons_text)
            features['has_brand_impersonation'] = float('brand impersonation' in reasons_text)
            features['has_data_uri_script'] = float('data uri' in reasons_text)
            features['favicon_mismatch'] = float('favicon' in reasons_text)

            # Count external forms
            features['external_form_count'] = self._extract_count_from_reasons(
                reasons_text, 'form'
            )

            # Count external scripts
            features['external_script_count'] = self._extract_count_from_reasons(
                reasons_text, 'external script'
            )

            # Count iframes
            features['iframe_count'] = self._extract_count_from_reasons(
                reasons_text, 'iframe'
            )

            # Hidden element ratio
            features['hidden_element_ratio'] = self._extract_ratio_from_reasons(
                reasons_text
            )

            # Urgency phrase count
            features['urgency_phrase_count'] = self._extract_count_from_reasons(
                reasons_text, 'urgency language'
            )
        else:
            features['has_password_form'] = 0.0
            features['external_form_count'] = 0.0
            features['external_script_count'] = 0.0
            features['iframe_count'] = 0.0
            features['hidden_element_ratio'] = 0.0
            features['has_obfuscated_js'] = 0.0
            features['has_brand_impersonation'] = 0.0
            features['has_data_uri_script'] = 0.0
            features['urgency_phrase_count'] = 0.0
            features['favicon_mismatch'] = 0.0

        # Network features
        features['redirect_count'] = float(redirect_count)
        features['requests_made_count'] = float(len(scrape_result.requests_made))

        return features

    @staticmethod
    def _calculate_entropy(s: str) -> float:
        """Calculate Shannon entropy"""
        import math

        if not s:
            return 0.0

        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1

        entropy = 0.0
        length = len(s)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def _calculate_digit_ratio(s: str) -> float:
        """Calculate ratio of digits in string"""
        if not s:
            return 0.0

        digit_count = sum(1 for c in s if c.isdigit())
        return digit_count / len(s)

    @staticmethod
    def _is_ip_address(hostname: str) -> bool:
        """Check if hostname is an IP address"""
        import re

        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        hostname_clean = hostname.split(':')[0]

        return bool(re.match(ipv4_pattern, hostname_clean))

    @staticmethod
    def _count_suspicious_keywords(url: str) -> int:
        """Count suspicious keywords in URL"""
        from app.analyzer.static import SUSPICIOUS_KEYWORDS

        url_lower = url.lower()
        count = 0

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                count += 1

        return count

    @staticmethod
    def _get_domain_age_days(domain: str) -> int:
        """Get domain age in days, -1 if unknown"""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age_days = (datetime.now() - creation_date).days
                return age_days
        except Exception as e:
            logger.debug("domain_age_lookup_failed", domain=domain, error=str(e))

        return -1

    @staticmethod
    def _get_min_typosquat_distance(domain: str) -> int:
        """Get minimum Levenshtein distance to known brands"""
        from app.analyzer.static import StaticAnalyzer

        domain_lower = domain.lower()
        min_distance = 999

        for brand in TOP_BRANDS:
            distance = StaticAnalyzer._levenshtein_distance(domain_lower, brand)
            min_distance = min(min_distance, distance)

        return min_distance

    @staticmethod
    def _extract_count_from_reasons(reasons_text: str, pattern: str) -> float:
        """Extract count from reason text (e.g., '3 iframe(s)' -> 3.0)"""
        import re

        match = re.search(rf'(\d+)\s+{pattern}', reasons_text)
        if match:
            return float(match.group(1))

        return 0.0

    @staticmethod
    def _extract_ratio_from_reasons(reasons_text: str) -> float:
        """Extract ratio from reason text (e.g., '(15%)' -> 0.15)"""
        import re

        match = re.search(r'\((\d+(?:\.\d+)?)%\)', reasons_text)
        if match:
            return float(match.group(1)) / 100.0

        return 0.0
