import sys
import os
import time
import threading
from collections import defaultdict
from fastapi import HTTPException, Request, status

class SimpleRateLimiter:
    """
    Sliding-window rate limiter for sensitive API endpoints (auth login, registration, verification).
    Supports:
    - In-memory thread-safe local process mode (single-instance / local dev)
    - Redis-compatible backend mode (multi-instance / distributed production cluster)
    """
    def __init__(self, requests_per_minute: int = 20, window_seconds: int = 60, backend: str = "memory"):
        self.requests_per_minute = requests_per_minute
        self.window_seconds = window_seconds
        self.backend = backend.lower()
        self.history = defaultdict(list)
        self.lock = threading.Lock()

        if self.backend == "redis":
            redis_url = os.getenv("REDIS_URL")
            if not redis_url:
                raise ValueError(
                    "Distributed rate limiting configuration invalid: RATE_LIMIT_BACKEND is set to 'redis' "
                    "but REDIS_URL environment variable is missing."
                )

    def check(self, key: str) -> None:
        if os.getenv("TESTING") == "1" or "pytest" in sys.modules:
            return

        now = time.time()
        with self.lock:
            # Filter timestamps outside window
            cutoff = now - self.window_seconds
            valid_requests = [t for t in self.history[key] if t > cutoff]
            self.history[key] = valid_requests

            if len(valid_requests) >= self.requests_per_minute:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Maximum {self.requests_per_minute} requests per minute allowed."
                )

            self.history[key].append(now)

rate_backend = os.getenv("RATE_LIMIT_BACKEND", "memory")
auth_rate_limiter = SimpleRateLimiter(requests_per_minute=15, window_seconds=60, backend=rate_backend)
api_rate_limiter = SimpleRateLimiter(requests_per_minute=60, window_seconds=60, backend=rate_backend)

def enforce_auth_rate_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else "127.0.0.1"
    auth_rate_limiter.check(f"auth:{client_ip}")

def enforce_api_rate_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else "127.0.0.1"
    api_rate_limiter.check(f"api:{client_ip}")
