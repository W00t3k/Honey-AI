"""
Lightweight Prometheus-compatible metrics for the AI honeypot.

Generates /metrics text in the standard Prometheus exposition format without
requiring the heavy prometheus_client package.  All counters are in-process
only; they reset on restart (which is fine — Prometheus tracks cumulative
values via time-series anyway).

Metrics exposed:
  honeypot_requests_total{protocol, classification, threat_level}
  honeypot_canary_hits_total
  honeypot_agent_trap_hits_total
  honeypot_analysis_errors_total
  honeypot_tarpit_delays_total
  honeypot_unique_ips_total  (gauge — approximate, in-memory HLL)
  honeypot_request_duration_seconds{quantile}  (summary)
"""

import math
import threading
import time
from collections import defaultdict
from typing import Optional


class _Counter:
    """Thread-safe monotonic counter."""

    def __init__(self, name: str, help_text: str, labels: list[str] = None):
        self.name = name
        self.help_text = help_text
        self.labels = labels or []
        self._lock = threading.Lock()
        self._values: dict[tuple, int] = defaultdict(int)

    def inc(self, label_values: tuple = (), n: int = 1):
        with self._lock:
            self._values[label_values] += n

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} counter",
        ]
        with self._lock:
            items = list(self._values.items())
        for lv, val in items:
            if self.labels and lv:
                label_str = ",".join(
                    f'{k}="{v}"' for k, v in zip(self.labels, lv)
                )
                lines.append(f"{self.name}{{{label_str}}} {val}")
            else:
                lines.append(f"{self.name} {val}")
        return "\n".join(lines)


class _Gauge:
    """Thread-safe gauge (can go up or down)."""

    def __init__(self, name: str, help_text: str, labels: list[str] = None):
        self.name = name
        self.help_text = help_text
        self.labels = labels or []
        self._lock = threading.Lock()
        self._values: dict[tuple, float] = defaultdict(float)

    def set(self, value: float, label_values: tuple = ()):
        with self._lock:
            self._values[label_values] = value

    def inc(self, label_values: tuple = (), n: float = 1.0):
        with self._lock:
            self._values[label_values] += n

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} gauge",
        ]
        with self._lock:
            items = list(self._values.items())
        for lv, val in items:
            if self.labels and lv:
                label_str = ",".join(
                    f'{k}="{v}"' for k, v in zip(self.labels, lv)
                )
                lines.append(f"{self.name}{{{label_str}}} {val}")
            else:
                lines.append(f"{self.name} {val}")
        return "\n".join(lines)


class _Summary:
    """
    Thread-safe request-duration summary.

    Tracks count, sum, and a fixed set of reservoir samples to compute
    approximate quantiles (p50, p90, p99).  Uses reservoir sampling so memory
    is bounded.
    """

    RESERVOIR_SIZE = 1024
    QUANTILES = [0.5, 0.90, 0.99]

    def __init__(self, name: str, help_text: str):
        self.name = name
        self.help_text = help_text
        self._lock = threading.Lock()
        self._count = 0
        self._sum = 0.0
        self._reservoir: list[float] = []

    def observe(self, value: float):
        import random
        with self._lock:
            self._count += 1
            self._sum += value
            if len(self._reservoir) < self.RESERVOIR_SIZE:
                self._reservoir.append(value)
            else:
                idx = random.randint(0, self._count - 1)
                if idx < self.RESERVOIR_SIZE:
                    self._reservoir[idx] = value

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} summary",
        ]
        with self._lock:
            count = self._count
            total = self._sum
            reservoir = sorted(self._reservoir)

        for q in self.QUANTILES:
            if reservoir:
                idx = min(int(math.ceil(q * len(reservoir))) - 1, len(reservoir) - 1)
                val = reservoir[idx]
            else:
                val = 0.0
            lines.append(f'{self.name}{{quantile="{q}"}} {val:.6f}')
        lines.append(f"{self.name}_sum {total:.6f}")
        lines.append(f"{self.name}_count {count}")
        return "\n".join(lines)


class _HyperLogLog:
    """
    Approximate cardinality counter (HLL, b=10 registers → ~1 % error).
    Used for unique IP estimation without storing all IPs.
    """

    B = 10
    M = 1 << B  # 1024 registers

    def __init__(self):
        self._registers = [0] * self.M
        self._lock = threading.Lock()
        self._alpha = 0.7213 / (1 + 1.079 / self.M)

    def add(self, value: str):
        import hashlib
        h = int(hashlib.md5(value.encode()).hexdigest(), 16)
        j = h & (self.M - 1)
        w = h >> self.B
        rho = 1
        while w & 1 == 0 and rho <= 64:
            w >>= 1
            rho += 1
        with self._lock:
            if rho > self._registers[j]:
                self._registers[j] = rho

    def estimate(self) -> int:
        with self._lock:
            regs = self._registers[:]
        z = 1.0 / sum(2.0 ** -r for r in regs)
        estimate = self._alpha * self.M * self.M * z
        return max(0, int(round(estimate)))


# ── Registry ───────────────────────────────────────────────────────────────────

class MetricsRegistry:
    """Singleton holding all honeypot metrics."""

    def __init__(self):
        self.requests_total = _Counter(
            "honeypot_requests_total",
            "Total honeypot requests received",
            ["protocol", "classification", "threat_level"],
        )
        self.canary_hits_total = _Counter(
            "honeypot_canary_hits_total",
            "Canary API key reuse detected",
        )
        self.agent_trap_hits_total = _Counter(
            "honeypot_agent_trap_hits_total",
            "LLM agent trap verification callbacks received",
        )
        self.analysis_errors_total = _Counter(
            "honeypot_analysis_errors_total",
            "Groq analysis errors",
        )
        self.tarpit_delays_total = _Counter(
            "honeypot_tarpit_delays_total",
            "Extra tarpit delay events applied to repeat abusers",
        )
        self.request_duration = _Summary(
            "honeypot_request_duration_seconds",
            "Request processing duration in seconds",
        )
        self._unique_ips = _HyperLogLog()
        self._unique_ips_gauge = _Gauge(
            "honeypot_unique_ips_approx",
            "Approximate number of unique source IPs seen (HyperLogLog)",
        )
        self._start_time = time.time()
        self._uptime_gauge = _Gauge(
            "honeypot_uptime_seconds",
            "Seconds since the honeypot process started",
        )

    def record_request(
        self,
        protocol: str = "unknown",
        classification: str = "unknown",
        threat_level: str = "unknown",
        duration_s: float = 0.0,
        source_ip: str = "",
    ):
        self.requests_total.inc((protocol, classification, threat_level or "unknown"))
        self.request_duration.observe(duration_s)
        if source_ip:
            self._unique_ips.add(source_ip)

    def record_canary_hit(self):
        self.canary_hits_total.inc()

    def record_agent_trap_hit(self):
        self.agent_trap_hits_total.inc()

    def record_analysis_error(self):
        self.analysis_errors_total.inc()

    def record_tarpit_delay(self):
        self.tarpit_delays_total.inc()

    def render(self) -> str:
        """Return Prometheus exposition-format text."""
        # Update live gauges
        self._unique_ips_gauge.set(float(self._unique_ips.estimate()))
        self._uptime_gauge.set(round(time.time() - self._start_time, 2))

        sections = [
            self.requests_total.render(),
            self.canary_hits_total.render(),
            self.agent_trap_hits_total.render(),
            self.analysis_errors_total.render(),
            self.tarpit_delays_total.render(),
            self.request_duration.render(),
            self._unique_ips_gauge.render(),
            self._uptime_gauge.render(),
        ]
        return "\n".join(sections) + "\n"


# ── Singleton ──────────────────────────────────────────────────────────────────
_registry: Optional[MetricsRegistry] = None


def get_metrics() -> MetricsRegistry:
    global _registry
    if _registry is None:
        _registry = MetricsRegistry()
    return _registry
