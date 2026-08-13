"""Content scraping module with SSRF protection"""
import socket
import ipaddress
from typing import List
from urllib.parse import urlparse
from playwright.async_api import async_playwright, Browser, Error as PlaywrightError
import structlog
from app.schemas import ScrapeResult
from app.core.config import settings

logger = structlog.get_logger(__name__)


class SSRFBlockedError(Exception):
    """Raised when SSRF protection blocks a request"""
    pass


class ScraperService:
    """Async web scraper with SSRF protection"""

    # Private IP ranges to block
    BLOCKED_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
    ]

    def __init__(self):
        self.timeout = settings.SCRAPER_TIMEOUT

    async def scrape(self, url: str) -> ScrapeResult:
        """
        Scrape URL content with SSRF protection.

        Args:
            url: URL to scrape

        Returns:
            ScrapeResult with HTML, title, final URL, and network requests
        """
        # SSRF protection - check before fetching
        try:
            self._check_ssrf(url)
        except SSRFBlockedError as e:
            logger.warning("ssrf_blocked", url=url, reason=str(e))
            return ScrapeResult(error=f"SSRF protection: {str(e)}")

        # Perform scraping
        try:
            return await self._scrape_with_playwright(url)
        except Exception as e:
            logger.error("scrape_failed", url=url, error=str(e))
            return ScrapeResult(error=str(e))

    def _check_ssrf(self, url: str) -> None:
        """
        Check for SSRF attempts by resolving hostname to IP.

        Args:
            url: URL to check

        Raises:
            SSRFBlockedError: If IP is in blocked range
        """
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            raise SSRFBlockedError("Invalid hostname")

        try:
            # Resolve hostname to IP addresses
            addr_info = socket.getaddrinfo(hostname, None)

            for info in addr_info:
                ip_str = info[4][0]
                ip = ipaddress.ip_address(ip_str)

                # Check against blocked ranges
                for blocked_range in self.BLOCKED_RANGES:
                    if ip in blocked_range:
                        raise SSRFBlockedError(
                            f"IP {ip_str} is in blocked range {blocked_range}"
                        )

        except SSRFBlockedError:
            raise
        except socket.gaierror as e:
            raise SSRFBlockedError(f"DNS resolution failed: {str(e)}")
        except Exception as e:
            raise SSRFBlockedError(f"IP validation failed: {str(e)}")

    async def _scrape_with_playwright(self, url: str) -> ScrapeResult:
        """
        Scrape URL using Playwright headless browser.

        Args:
            url: URL to scrape

        Returns:
            ScrapeResult with content
        """
        network_requests: List[str] = []
        console_errors: List[str] = []

        async with async_playwright() as p:
            browser: Browser = await p.chromium.launch(
                args=[
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--disable-extensions",
                    "--disable-background-networking",
                ]
            )

            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )

            page = await context.new_page()

            # Track network requests
            page.on("request", lambda request: network_requests.append(request.url))

            # Track console errors
            page.on("console", lambda msg: (
                console_errors.append(msg.text)
                if msg.type == "error" else None
            ))

            try:
                # Navigate with timeout
                await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=self.timeout
                )

                # Wait a bit for dynamic content
                await page.wait_for_timeout(1000)

                # Extract data
                html = await page.content()
                title = await page.title()
                final_url = page.url

                result = ScrapeResult(
                    html=html,
                    title=title,
                    final_url=final_url,
                    requests_made=network_requests,
                    error=None
                )

                logger.info(
                    "scrape_success",
                    url=url,
                    final_url=final_url,
                    requests_count=len(network_requests),
                    title=title[:50] if title else None
                )

                return result

            except PlaywrightError as e:
                logger.warning("playwright_error", url=url, error=str(e))
                return ScrapeResult(error=f"Playwright error: {str(e)}")

            except Exception as e:
                logger.error("scrape_exception", url=url, error=str(e))
                return ScrapeResult(error=str(e))

            finally:
                await context.close()
                await browser.close()
