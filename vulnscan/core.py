import time
import threading
import requests
from collections import deque
from urllib.parse import urljoin, urlparse, urlencode
from typing import Dict, Any, List, Optional, Deque, Tuple, Callable

DEFAULT_HEADER_NAME = "X-BugBounty"
DEFAULT_HEADER_VALUE = "e587b4d9-5dc2-4a6d-87d0-a46984a87b63"

class RateLimiter:
    def __init__(self, max_rps: float):
        self.max_rps = max_rps
        self._lock = threading.Lock()
        self._timestamps: List[float] = []

    def acquire(self):
        if self.max_rps <= 0:
            return
        with self._lock:
            now = time.time()
            window_start = now - 1.0
            # remove old
            self._timestamps = [t for t in self._timestamps if t >= window_start]
            if len(self._timestamps) >= self.max_rps:
                sleep_for = 1.0 - (now - self._timestamps[0])
                if sleep_for > 0:
                    time.sleep(sleep_for)
            self._timestamps.append(time.time())

class HttpClient:
    def __init__(self, base_url: str, max_rps: float = 5.0, timeout: int = 12, extra_headers: Optional[Dict[str,str]] = None, max_requests: Optional[int] = None, adaptive: bool = True, on_adaptive_event: Optional[Callable[[str, float], None]] = None):
        self.base_url = base_url if base_url.endswith('/') else base_url + '/'
        self.timeout = timeout
        self.session = requests.Session()
        self.rate = RateLimiter(max_rps)
        self.base_rps = max_rps
        self.adaptive = adaptive
        self.on_adaptive_event = on_adaptive_event
        self.default_headers = {
            DEFAULT_HEADER_NAME: DEFAULT_HEADER_VALUE,
            'User-Agent': 'VulnScan/0.2 (+ethical)'
        }
        if extra_headers:
            self.default_headers.update(extra_headers)
        self.max_requests = max_requests
        self._request_count = 0
        # simple in-memory cache for idempotent GET root & static resources
        self._cache: Dict[str, requests.Response] = {}
        # adaptive stats
        self._recent: Deque[Tuple[bool,int]] = deque(maxlen=30)  # (success, status_code)
        self._last_adjust = 0.0

    def _inc(self):
        self._request_count += 1
        if self.max_requests and self._request_count > self.max_requests:
            raise RuntimeError(f'Max requests limit reached ({self.max_requests})')

    # Adaptive RPS logic: monitor recent failures (>=500 or status 0) and adjust rate
    def _record(self, status_code: int, success: bool):
        if not self.adaptive:
            return
        self._recent.append((success, status_code))
        # Only consider if we have at least 8 samples and at least 2 seconds since last adjust
        if len(self._recent) < 8:
            return
        now = time.time()
        if now - self._last_adjust < 2.0:
            return
        failures = 0
        for ok, sc in self._recent:
            if (not ok) or sc >= 500 or sc == 0:
                failures += 1
        ratio = failures / len(self._recent)
        # Decrease threshold
        if ratio >= 0.40 and self.rate.max_rps > max(self.base_rps * 0.30, 0.5):
            new_rps = max(self.base_rps * 0.30, self.rate.max_rps * 0.70)
            self.rate.max_rps = new_rps
            self._last_adjust = now
            if self.on_adaptive_event:
                self.on_adaptive_event('decrease', new_rps)
        # Increase back slowly if healthy
        elif ratio <= 0.10 and self.rate.max_rps < self.base_rps:
            new_rps = min(self.base_rps, self.rate.max_rps * 1.10)
            if abs(new_rps - self.rate.max_rps) > 0.01:
                self.rate.max_rps = new_rps
                self._last_adjust = now
                if self.on_adaptive_event:
                    self.on_adaptive_event('increase', new_rps)

    def build_url(self, path: str) -> str:
        if path.startswith('http://') or path.startswith('https://'):
            return path
        return urljoin(self.base_url, path.lstrip('/'))

    def get(self, path: str, params: Optional[Dict[str, Any]] = None, allow_redirects: bool = True, headers: Optional[Dict[str,str]] = None, no_cache: bool = False) -> requests.Response:
        url = self.build_url(path)
        cache_key = None
        if not params and path in ('', '/') and not headers and not no_cache:
            cache_key = f"GET::{url}"
            if cache_key in self._cache:
                return self._cache[cache_key]
        self.rate.acquire()
        self._inc()
        all_headers = dict(self.default_headers)
        if headers:
            all_headers.update(headers)
        try:
            resp = self.session.get(url, params=params, headers=all_headers, timeout=self.timeout, allow_redirects=allow_redirects)
            self._record(resp.status_code, True)
        except requests.RequestException:
            self._record(0, False)
            raise
        if cache_key and resp.status_code == 200:
            self._cache[cache_key] = resp
        return resp

    def head(self, path: str) -> requests.Response:
        self.rate.acquire()
        url = self.build_url(path)
        self._inc()
        try:
            resp = self.session.head(url, headers=self.default_headers, timeout=self.timeout, allow_redirects=True)
            self._record(resp.status_code, True)
            return resp
        except requests.RequestException:
            self._record(0, False)
            raise

    def options(self, path: str, headers: Optional[Dict[str,str]] = None) -> requests.Response:
        self.rate.acquire()
        url = self.build_url(path)
        self._inc()
        all_headers = dict(self.default_headers)
        if headers:
            all_headers.update(headers)
        try:
            resp = self.session.options(url, headers=all_headers, timeout=self.timeout, allow_redirects=True)
            self._record(resp.status_code, True)
            return resp
        except requests.RequestException:
            self._record(0, False)
            raise

    def request_variant(self, url: str, params: Dict[str, Any]) -> requests.Response:
        self.rate.acquire()
        self._inc()
        try:
            resp = self.session.get(url, params=params, headers=self.default_headers, timeout=self.timeout, allow_redirects=True)
            self._record(resp.status_code, True)
            return resp
        except requests.RequestException:
            self._record(0, False)
            raise

class Finding:
    def __init__(self, module: str, severity: str, title: str, detail: str):
        self.module = module
        self.severity = severity
        self.title = title
        self.detail = detail
    def to_dict(self):
        return {
            'module': self.module,
            'severity': self.severity,
            'title': self.title,
            'detail': self.detail
        }

SecurityFinding = Finding
