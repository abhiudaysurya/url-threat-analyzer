"""Static URL analysis module"""
import math
import re
import socket
from datetime import datetime
from typing import List, Tuple
from urllib.parse import urlparse, parse_qs
import whois
import tldextract
import httpx
import structlog
from app.schemas import AnalysisResult
from app.core.config import settings

logger = structlog.get_logger(__name__)

# Top 20 brands for typosquatting detection
TOP_BRANDS = [
    "google", "facebook", "paypal", "amazon", "apple",
    "microsoft", "netflix", "instagram", "twitter", "linkedin",
    "dropbox", "chase", "wellsfargo", "bankofamerica", "gmail",
    "outlook", "yahoo", "steam", "coinbase", "binance"
]

# High-risk TLDs
HIGH_RISK_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".pw", ".click", ".link"
}

# Suspicious keywords
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "secure", "update",
    "confirm", "account", "password", "credential", "banking"
}


class StaticAnalyzer:
    """Performs static URL analysis without fetching content"""

    def __init__(self):
        self.safe_browsing_api_key = settings.SAFE_BROWSING_API_KEY

    def analyze(self, url: str) -> AnalysisResult:
        """
        Run all static checks on the URL.

        Args:
            url: URL to analyze

        Returns:
            AnalysisResult with score and reasons
        """
        reasons = []
        weights = []

        # Check 1: Google Safe Browsing (HIGHEST PRIORITY - CHECK FIRST)
        # If GSB detects a threat, return immediately without further processing
        gsb_weight = self._check_safe_browsing(url, reasons)
        if gsb_weight > 0:
            logger.info("gsb_threat_detected", url=url, immediate_return=True)
            return AnalysisResult(score=1.0, reasons=reasons)

        # Continue with other checks only if GSB didn't detect a threat
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        hostname = parsed.netloc.lower()

        # Check 2: Domain age
        age_weight = self._check_domain_age(ext.registered_domain, reasons)
        if age_weight > 0:
            weights.append(age_weight)

        # Check 3: URL entropy
        entropy_weight = self._check_url_entropy(hostname, reasons)
        if entropy_weight > 0:
            weights.append(entropy_weight)

        # Check 4: Subdomain depth
        subdomain_weight = self._check_subdomain_depth(ext.subdomain, reasons)
        if subdomain_weight > 0:
            weights.append(subdomain_weight)

        # Check 5: IP as hostname
        ip_weight = self._check_ip_hostname(hostname, reasons)
        if ip_weight > 0:
            weights.append(ip_weight)

        # Check 6: Typosquatting
        typo_weight = self._check_typosquatting(ext.domain, reasons)
        if typo_weight > 0:
            weights.append(typo_weight)

        # Check 7: Suspicious keywords
        keyword_weight = self._check_suspicious_keywords(url, reasons)
        if keyword_weight > 0:
            weights.append(keyword_weight)

        # Check 8: High-risk TLD
        tld_weight = self._check_high_risk_tld(ext.suffix, reasons)
        if tld_weight > 0:
            weights.append(tld_weight)

        # Check 9: Excessive URL length
        length_weight = self._check_url_length(url, reasons)
        if length_weight > 0:
            weights.append(length_weight)

        # Check 10: Redirect count
        redirect_weight = self._check_redirects(url, reasons)
        if redirect_weight > 0:
            weights.append(redirect_weight)

        # Calculate final score
        score = sum(weights) / len(weights) if weights else 0.0
        score = min(score, 1.0)

        return AnalysisResult(score=score, reasons=reasons)

    def _check_domain_age(self, domain: str, reasons: List[str]) -> float:
        """Check domain age via WHOIS"""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age_days = (datetime.now() - creation_date).days
                if age_days < 30:
                    reasons.append(f"Domain registered only {age_days} days ago")
                    return 0.7
        except Exception as e:
            logger.debug("whois_lookup_failed", domain=domain, error=str(e))

        return 0.0

    def _check_url_entropy(self, hostname: str, reasons: List[str]) -> float:
        """Calculate Shannon entropy of hostname"""
        if not hostname:
            return 0.0

        entropy = self._calculate_entropy(hostname)
        if entropy > 3.5:
            reasons.append(f"High URL entropy ({entropy:.2f} bits)")
            return 0.5

        return 0.0

    @staticmethod
    def _calculate_entropy(s: str) -> float:
        """Calculate Shannon entropy"""
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

    def _check_subdomain_depth(self, subdomain: str, reasons: List[str]) -> float:
        """Check the number of subdomains"""
        if not subdomain:
            return 0.0

        parts = subdomain.split('.')
        if len(parts) > 3:
            reasons.append(f"Excessive subdomain depth ({len(parts)} levels)")
            return 0.4

        return 0.0

    def _check_ip_hostname(self, hostname: str, reasons: List[str]) -> float:
        """Check if the hostname is a raw IP address"""
        # IPv4 pattern
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$'
        # IPv6 pattern (simplified)
        ipv6_pattern = r'^\[?[0-9a-f:]+\]?(:\d+)?$'

        hostname_clean = hostname.split(':')[0]  # Remove port

        if re.match(ipv4_pattern, hostname) or re.match(ipv6_pattern, hostname.lower()):
            reasons.append("URL uses raw IP address instead of domain")
            return 0.8

        return 0.0

    def _check_typosquatting(self, domain: str, reasons: List[str]) -> float:
        """Check for typosquatting against known brands"""
        domain_lower = domain.lower()

        for brand in TOP_BRANDS:
            distance = self._levenshtein_distance(domain_lower, brand)
            if distance <= 2 and distance > 0:
                reasons.append(f"Possible typosquatting of '{brand}' (distance: {distance})")
                return 0.75

        return 0.0

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return StaticAnalyzer._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _check_suspicious_keywords(self, url: str, reasons: List[str]) -> float:
        """Check for suspicious keywords in URL path/query"""
        url_lower = url.lower()
        found_keywords = []

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                found_keywords.append(keyword)

        if found_keywords:
            reasons.append(f"Suspicious keywords in URL: {', '.join(found_keywords)}")
            return 0.5

        return 0.0

    def _check_high_risk_tld(self, tld: str, reasons: List[str]) -> float:
        """Check for high-risk TLD"""
        tld_with_dot = f".{tld}" if not tld.startswith('.') else tld

        if tld_with_dot in HIGH_RISK_TLDS:
            reasons.append(f"High-risk TLD: {tld_with_dot}")
            return 0.4

        return 0.0

    def _check_url_length(self, url: str, reasons: List[str]) -> float:
        """Check for excessive URL length"""
        if len(url) > 100:
            reasons.append(f"Excessive URL length ({len(url)} characters)")
            return 0.3

        return 0.0

    from typing import List
    import httpx
    # Assuming logger is imported/defined globally or at the class level

    def _check_safe_browsing(self, url: str, reasons: List[str]) -> float:
        """Check Google Safe Browsing API"""
        if not self.safe_browsing_api_key:
            return 0.0

        try:
            api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            params = {"key": self.safe_browsing_api_key}

            payload = {
                "client": {
                    "clientId": "url-analyzer",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }

            # Note: For high-volume checking, consider making `self.client` a persistent
            # httpx.Client instance on the class rather than creating a new one per call.
            with httpx.Client(timeout=5.0) as client:
                response = client.post(api_url, params=params, json=payload)

                if response.status_code == 200:
                    data = response.json()
                    if data.get("matches"):
                        # Use set() to deduplicate threat types
                        threat_types = set(m.get("threatType") for m in data["matches"] if m.get("threatType"))
                        reasons.append(f"Google Safe Browsing threat detected: {', '.join(threat_types)}")
                        return 1.0
                else:
                    # Log HTTP errors (like 429 Quota Exceeded or 403 Forbidden)
                    logger.warning(
                        "safe_browsing_api_error",
                        status_code=response.status_code,
                        response_text=response.text
                    )

        except httpx.RequestError as e:
            # Catch specific network errors separately if you want to distinguish timeouts/connection issues
            logger.warning("safe_browsing_network_error", error=str(e))
        except Exception as e:
            logger.warning("safe_browsing_check_failed", error=str(e))

        return 0.0

    def _check_redirects(self, url: str, reasons: List[str]) -> float:
        """Check redirect count"""
        try:
            with httpx.Client(
                follow_redirects=True,
                max_redirects=10,
                timeout=5.0
            ) as client:
                response = client.head(url)
                redirect_count = len(response.history)

                if redirect_count > 2:
                    reasons.append(f"Excessive redirects ({redirect_count} hops)")
                    return 0.4

        except Exception as e:
            logger.debug("redirect_check_failed", url=url, error=str(e))

        return 0.0
