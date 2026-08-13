"""In-memory API performance metrics."""
from __future__ import annotations

import asyncio
import time
from collections import Counter, defaultdict, deque


class APIMetrics:
    """Collect simple request and latency metrics for the API."""

    def __init__(self, window_size: int = 5000) -> None:
        self._window_size = window_size
        self._lock = asyncio.Lock()
        self._started_at = time.perf_counter()
        self._last_request_at = self._started_at
        self._total_requests = 0
        self._total_latency_ms = 0.0
        self._status_counts: Counter[str] = Counter()
        self._path_counts: Counter[str] = Counter()
        self._path_latency_ms: defaultdict[str, float] = defaultdict(float)
        self._recent_latencies_ms = deque(maxlen=window_size)
        self._active_requests = 0
        self._peak_active_requests = 0
        self._cache_hits = 0

    async def record_request(self, path: str, status_code: int, duration_ms: float) -> None:
        """Record a completed request."""
        async with self._lock:
            self._total_requests += 1
            self._total_latency_ms += duration_ms
            self._last_request_at = time.perf_counter()
            self._status_counts[str(status_code)] += 1
            self._path_counts[path] += 1
            self._path_latency_ms[path] += duration_ms
            self._recent_latencies_ms.append(duration_ms)

    async def record_cache_hit(self) -> None:
        """Record a cache hit for analysis requests."""
        async with self._lock:
            self._cache_hits += 1

    async def request_started(self) -> None:
        """Track concurrent in-flight requests."""
        async with self._lock:
            self._active_requests += 1
            self._peak_active_requests = max(self._peak_active_requests, self._active_requests)

    async def request_finished(self) -> None:
        """Reduce the in-flight request count."""
        async with self._lock:
            self._active_requests = max(0, self._active_requests - 1)

    async def snapshot(self) -> dict:
        """Return a serializable metrics snapshot."""
        async with self._lock:
            now = time.perf_counter()
            uptime_seconds = max(now - self._started_at, 0.0)
            average_latency_ms = (
                self._total_latency_ms / self._total_requests if self._total_requests else 0.0
            )
            latencies = list(self._recent_latencies_ms)
            latencies.sort()

            def percentile(value: float) -> float:
                if not latencies:
                    return 0.0
                index = int(round((len(latencies) - 1) * value))
                index = max(0, min(index, len(latencies) - 1))
                return latencies[index]

            path_metrics = {
                path: {
                    "requests": count,
                    "average_latency_ms": round(self._path_latency_ms[path] / count, 3),
                }
                for path, count in self._path_counts.items()
            }

            cache_hit_rate = (
                self._cache_hits / self._total_requests if self._total_requests else 0.0
            )

            return {
                "uptime_seconds": round(uptime_seconds, 3),
                "total_requests": self._total_requests,
                "requests_per_second": round(
                    self._total_requests / uptime_seconds if uptime_seconds else 0.0, 3
                ),
                "active_requests": self._active_requests,
                "peak_active_requests": self._peak_active_requests,
                "average_latency_ms": round(average_latency_ms, 3),
                "min_latency_ms": round(min(latencies), 3) if latencies else 0.0,
                "max_latency_ms": round(max(latencies), 3) if latencies else 0.0,
                "p50_latency_ms": round(percentile(0.50), 3),
                "p95_latency_ms": round(percentile(0.95), 3),
                "p99_latency_ms": round(percentile(0.99), 3),
                "status_counts": dict(self._status_counts),
                "path_metrics": path_metrics,
                "cache_hits": self._cache_hits,
                "cache_hit_rate": round(cache_hit_rate, 3),
                "last_request_age_seconds": round(now - self._last_request_at, 3),
            }

    async def reset(self) -> None:
        """Clear collected metrics, useful for tests."""
        async with self._lock:
            self._started_at = time.perf_counter()
            self._last_request_at = self._started_at
            self._total_requests = 0
            self._total_latency_ms = 0.0
            self._status_counts.clear()
            self._path_counts.clear()
            self._path_latency_ms.clear()
            self._recent_latencies_ms.clear()
            self._active_requests = 0
            self._peak_active_requests = 0
            self._cache_hits = 0


metrics = APIMetrics()