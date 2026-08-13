"""Verdict orchestrator - coordinates all analysis components"""
import time
import hashlib
from urllib.parse import urlparse
import structlog
from app.schemas import VerdictResponse, AnalysisResult
from app.analyzer.static import StaticAnalyzer
from app.analyzer.scraper import ScraperService
from app.analyzer.dom_signals import DOMAnalyzer
from app.analyzer.features import FeatureExtractor
from app.ml.model import threat_model

logger = structlog.get_logger(__name__)


class URLValidator:
    """Validates URL format"""

    @staticmethod
    def validate(url: str) -> None:
        """
        Validate URL format.

        Args:
            url: URL to validate

        Raises:
            ValueError: If URL is invalid
        """
        if not url:
            raise ValueError("URL cannot be empty")

        if len(url) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters")

        try:
            parsed = urlparse(url)

            if not parsed.scheme:
                raise ValueError("URL must include a scheme (http:// or https://)")

            if parsed.scheme not in ['http', 'https']:
                raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")

            if not parsed.netloc:
                raise ValueError("URL must include a hostname")

        except Exception as e:
            raise ValueError(f"Invalid URL format: {str(e)}")


async def analyze_url(url: str) -> VerdictResponse:
    """
    Orchestrate complete URL threat analysis.

    This function coordinates all analysis components:
    1. Validate URL format
    2. Run static analysis
    3. Run content scraping (skip if static score > 0.9)
    4. Run DOM analysis (skip if scrape failed)
    5. Extract features
    6. Run ML model prediction
    7. Aggregate verdict and return response

    Args:
        url: URL to analyze

    Returns:
        VerdictResponse with verdict, confidence, and reasons

    Raises:
        ValueError: If URL format is invalid
    """
    start_time = time.time()

    # Generate URL hash for logging
    url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]

    logger.info("analysis_started", url_hash=url_hash, url=url)

    try:
        # Step 1: Validate URL
        URLValidator.validate(url)

        # Initialize components
        static_analyzer = StaticAnalyzer()
        scraper = ScraperService()
        dom_analyzer = DOMAnalyzer()
        feature_extractor = FeatureExtractor()

        all_reasons = []
        checks_run = []

        # Step 2: Run static analysis (always)
        logger.info("running_static_analysis", url_hash=url_hash)
        static_result = static_analyzer.analyze(url)
        all_reasons.extend(static_result.reasons)
        checks_run.append("static")

        logger.info(
            "static_analysis_complete",
            url_hash=url_hash,
            score=static_result.score,
            reason_count=len(static_result.reasons)
        )

        # Step 3: Run scraping (skip if clearly malicious)
        scrape_result = None
        dom_result = None

        if static_result.score < 0.9:
            logger.info("running_scraper", url_hash=url_hash)

            try:
                scrape_result = await scraper.scrape(url)
                checks_run.append("scraper")

                if scrape_result.error:
                    logger.warning(
                        "scrape_failed",
                        url_hash=url_hash,
                        error=scrape_result.error
                    )
                    all_reasons.append(f"Scraping failed: {scrape_result.error}")

            except Exception as e:
                logger.error("scraper_exception", url_hash=url_hash, error=str(e))
                all_reasons.append(f"Scraping error: {str(e)}")

            # Step 4: Run DOM analysis (if scrape succeeded)
            if scrape_result and scrape_result.is_successful:
                logger.info("running_dom_analysis", url_hash=url_hash)

                try:
                    dom_result = dom_analyzer.analyze(
                        scrape_result.html,
                        scrape_result.final_url or url
                    )
                    all_reasons.extend(dom_result.reasons)
                    checks_run.append("dom")

                    logger.info(
                        "dom_analysis_complete",
                        url_hash=url_hash,
                        score=dom_result.score,
                        reason_count=len(dom_result.reasons)
                    )

                except Exception as e:
                    logger.error("dom_analysis_exception", url_hash=url_hash, error=str(e))
                    all_reasons.append(f"DOM analysis error: {str(e)}")
                    dom_result = AnalysisResult(score=0.0, reasons=[])
            else:
                dom_result = AnalysisResult(score=0.0, reasons=[])
        else:
            logger.info(
                "skipping_scraping",
                url_hash=url_hash,
                reason="Static score > 0.9"
            )
            dom_result = AnalysisResult(score=0.0, reasons=[])

        # Step 5: Extract features
        logger.info("extracting_features", url_hash=url_hash)
        features = feature_extractor.extract_features(
            url=url,
            static_result=static_result,
            dom_result=dom_result,
            scrape_result=scrape_result,
            redirect_count=0
        )

        # Step 6: Run ML model prediction
        logger.info("running_ml_prediction", url_hash=url_hash)
        ml_verdict, ml_confidence = threat_model.predict(features)
        checks_run.append("ml_model")

        logger.info(
            "ml_prediction_complete",
            url_hash=url_hash,
            ml_verdict=ml_verdict,
            ml_confidence=ml_confidence
        )

        # Step 7: Aggregate verdict
        # Check if Google Safe Browsing detected a threat (HIGH PRIORITY)
        has_gsb_threat = any('Google Safe Browsing' in reason or 'safe browsing' in reason.lower()
                            for reason in static_result.reasons)

        if has_gsb_threat:
            # If Google Safe Browsing detected a threat, override with malicious verdict
            combined_score = 0.95
            final_verdict = "malicious"
        else:
            # Trust the ML model verdict directly when it's available
            # The ML model already considers all features including static and DOM scores
            final_verdict = ml_verdict
            combined_score = ml_confidence

            logger.info(
                "using_ml_verdict",
                url_hash=url_hash,
                ml_verdict=ml_verdict,
                ml_confidence=ml_confidence,
                static_score=static_result.score,
                dom_score=dom_result.score
            )

        # Deduplicate and sort reasons
        unique_reasons = list(dict.fromkeys(all_reasons))  # Preserve order while deduplicating

        # Sort by severity (malicious indicators first)
        severity_keywords = [
            'safe browsing', 'obfuscated', 'brand impersonation',
            'password', 'external form', 'typosquatting',
            'high-risk', 'excessive', 'urgency'
        ]

        def reason_severity(reason: str) -> int:
            """Calculate severity score for sorting"""
            reason_lower = reason.lower()
            for i, keyword in enumerate(severity_keywords):
                if keyword in reason_lower:
                    return i
            return 999

        sorted_reasons = sorted(unique_reasons, key=reason_severity)

        # Calculate analysis time
        analysis_time_ms = int((time.time() - start_time) * 1000)

        # Create response
        response = VerdictResponse(
            url=url,
            verdict=final_verdict,
            confidence=round(combined_score, 3),
            reasons=sorted_reasons,
            cached=False,
            analysis_time_ms=analysis_time_ms
        )

        logger.info(
            "analysis_complete",
            url_hash=url_hash,
            verdict=final_verdict,
            confidence=combined_score,
            analysis_time_ms=analysis_time_ms,
            checks_run=checks_run,
            reason_count=len(sorted_reasons)
        )

        return response

    except ValueError as e:
        # Validation error
        logger.warning("validation_failed", url_hash=url_hash, error=str(e))
        raise

    except Exception as e:
        # Unexpected error
        logger.error("analysis_failed", url_hash=url_hash, error=str(e), exc_info=True)

        # Return a safe default response rather than crashing
        analysis_time_ms = int((time.time() - start_time) * 1000)

        return VerdictResponse(
            url=url,
            verdict="suspicious",
            confidence=0.5,
            reasons=[f"Analysis error: {str(e)}"],
            cached=False,
            analysis_time_ms=analysis_time_ms
        )
