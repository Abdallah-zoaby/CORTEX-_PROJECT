
import time
import asyncio
import random
import logging
from typing import Dict, Any

logger = logging.getLogger("TitaniumScanner")

class SmartRateLimiter:
    """Intelligent rate limiting with adaptive throttling"""
    
    def __init__(self, max_rpm: int = 60):
        self.max_rpm = max_rpm
        self.requests = {}
        self.blocked_domains = {}
        self.adaptive_delays = {}
    
    async def wait_if_needed(self, domain: str):
        """Wait if rate limiting is needed"""
        now = time.time()
        
        # Clean old requests
        if domain in self.requests:
            self.requests[domain] = [
                t for t in self.requests[domain]
                if now - t < 60
            ]
        
        # Check if domain is blocked
        if domain in self.blocked_domains:
            block_until = self.blocked_domains[domain]
            if now < block_until:
                wait_time = block_until - now
                logger.warning(f"⚠️ Domain {domain} blocked, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)
                del self.blocked_domains[domain]
        
        # Apply adaptive delay
        if domain in self.adaptive_delays:
            delay = self.adaptive_delays[domain]
            await asyncio.sleep(delay)
        
        # Check rate limit
        if domain not in self.requests:
            self.requests[domain] = []
        
        if len(self.requests[domain]) >= self.max_rpm:
            # Calculate wait time
            oldest = self.requests[domain][0]
            wait_time = 60 - (now - oldest)
            if wait_time > 0:
                logger.info(f"⏳ Rate limit reached for {domain}, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)
        
        self.requests[domain].append(now)
    
    def handle_429(self, domain: str):
        """Handle 429 Too Many Requests response"""
        self.blocked_domains[domain] = time.time() + random.uniform(30, 90)
        logger.warning(f"⚡ Rate limited by {domain}, backing off")
    
    def adjust_delay(self, domain: str, response_time: float):
        """Adaptively adjust delays based on response time"""
        if domain not in self.adaptive_delays:
            self.adaptive_delays[domain] = 0.5
        
        if response_time > 5:
            # Increase delay for slow servers
            self.adaptive_delays[domain] = min(
                self.adaptive_delays[domain] * 1.2,
                2.0
            )
        elif response_time < 1:
            # Decrease delay for fast servers
            self.adaptive_delays[domain] = max(
                self.adaptive_delays[domain] * 0.8,
                0.1
            )

class CacheManager:
    """Intelligent caching system"""
    
    def __init__(self, ttl: int = 300):
        self.ttl = ttl
        self.cache = {}
        self.hits = 0
        self.misses = 0
    
    def get(self, key: str):
        """Get cached item"""
        if key in self.cache:
            item, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                self.hits += 1
                return item
            else:
                del self.cache[key]
        self.misses += 1
        return None
    
    def set(self, key: str, value: Any):
        """Set cache item"""
        self.cache[key] = (value, time.time())
    
    def clear(self):
        """Clear cache"""
        self.cache.clear()
    
    def stats(self) -> Dict:
        """Get cache statistics"""
        total = self.hits + self.misses
        hit_rate = (self.hits / total) * 100 if total > 0 else 0
        return {
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': hit_rate,
            'size': len(self.cache)
        }
