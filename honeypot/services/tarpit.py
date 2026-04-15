"""
IP tarpit service.

Tracks request rates per source IP and introduces exponential delays for
repeat abusers, slowing down automated scanners without breaking legitimate
one-off probes (which are still interesting to us).

Thresholds (configurable via config.json):
  tarpit_rpm_threshold  — requests per minute before tarpitting starts (default 20)
  tarpit_max_delay_s    — maximum added delay in seconds (default 30)

The tarpit is transparent to the attacker: responses still succeed, they just
take longer.  This wastes scanner resources while keeping the honeypot alive
long enough to log everything.
"""

import asyncio
import time
import threading
from collections import defaultdict, deque
from typing import Optional

from rich.console import Console

console = Console()


class TarpitService:
    """Rate-tracks IPs and computes tarpit delays."""

    def __init__(
        self,
        rpm_threshold: int = 20,
        max_delay_s: float = 30.0,
        window_s: int = 60,
    ):
        self.rpm_threshold = rpm_threshold
        self.max_delay_s = max_delay_s
        self.window_s = window_s

        # Per-IP sliding window of request timestamps
        self._windows: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

        # Reload from config
        self._reload()

    def _reload(self):
        try:
            from services.config import get_config
            cfg = get_config()
            self.rpm_threshold = int(cfg.get("tarpit_rpm_threshold", self.rpm_threshold) or self.rpm_threshold)
            self.max_delay_s = float(cfg.get("tarpit_max_delay_s", self.max_delay_s) or self.max_delay_s)
        except Exception:
            pass

    def record_and_get_delay(self, ip: str) -> float:
        """
        Record a request from `ip` and return the tarpit delay in seconds.

        A delay of 0.0 means no tarpitting.
        """
        now = time.monotonic()
        cutoff = now - self.window_s

        with self._lock:
            window = self._windows[ip]
            # Evict old entries
            while window and window[0] < cutoff:
                window.popleft()
            window.append(now)
            count = len(window)

        if count <= self.rpm_threshold:
            return 0.0

        # Exponential backoff: delay doubles every threshold requests
        excess = count - self.rpm_threshold
        # 0.1 s × 2^(excess/threshold), capped at max_delay_s
        delay = min(0.1 * (2 ** (excess / max(self.rpm_threshold, 1))), self.max_delay_s)
        return delay

    async def apply(self, ip: str) -> None:
        """
        Apply tarpit delay (async sleep) for the given IP.
        Records the request regardless.
        """
        delay = self.record_and_get_delay(ip)
        if delay > 0.0:
            from services.metrics import get_metrics
            get_metrics().record_tarpit_delay()
            console.print(
                f"[dim yellow]Tarpit: {ip} +{delay:.1f}s delay "
                f"({self.record_and_get_delay.__doc__ and '' or ''})[/dim yellow]",
                highlight=False,
            )
            await asyncio.sleep(delay)

    def cleanup_old_ips(self, max_ips: int = 50_000) -> None:
        """Prune the oldest IP entries to bound memory usage."""
        with self._lock:
            if len(self._windows) > max_ips:
                # Remove IPs with the oldest last-request timestamps
                sorted_ips = sorted(
                    self._windows.items(),
                    key=lambda kv: kv[1][-1] if kv[1] else 0,
                )
                for ip, _ in sorted_ips[: len(self._windows) - max_ips]:
                    del self._windows[ip]


_tarpit: Optional[TarpitService] = None


def get_tarpit() -> TarpitService:
    global _tarpit
    if _tarpit is None:
        _tarpit = TarpitService()
    return _tarpit
