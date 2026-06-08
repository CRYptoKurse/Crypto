import time
from collections import defaultdict
from flask import request, Response

class TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self.tokens = defaultdict(float)
        self.last = defaultdict(float)

    def allow(self, key: str) -> bool:
        now = time.time()
        if key not in self.tokens:
            self.tokens[key] = self.burst
            self.last[key] = now
            return True
        elapsed = now - self.last[key]
        self.tokens[key] = min(self.burst, self.tokens[key] + elapsed * self.rate)
        self.last[key] = now
        if self.tokens[key] >= 1.0:
            self.tokens[key] -= 1.0
            return True
        return False

def rate_limit_middleware(app, rate: float, burst: int):
    if rate <= 0:
        return
    bucket = TokenBucket(rate, burst)
    @app.before_request
    def limit():
        client_ip = request.remote_addr
        if not bucket.allow(client_ip):
            resp = Response("Rate limit exceeded", status=429)
            resp.headers['Retry-After'] = '5'
            return resp