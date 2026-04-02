package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type IPRateLimiter struct {
	ips map[string]*Visitor
	mu  sync.RWMutex
	r   rate.Limit
	ttl time.Duration
	b   int
}

type Visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewIPRateLimiter(rateLimit rate.Limit, ttl time.Duration, b int) *IPRateLimiter {
	return &IPRateLimiter{
		ips: make(map[string]*Visitor),
		mu:  sync.RWMutex{},
		r:   rateLimit,
		ttl: ttl,
		b:   b,
	}
}

func (rl *IPRateLimiter) Cleanup() {
	cutoff := time.Now().Add(-rl.ttl)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for ip, v := range rl.ips {
		if v.lastSeen.Before(cutoff) {
			delete(rl.ips, ip)
		}
	}
}

func (rl *IPRateLimiter) StartCleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rl.Cleanup()
			}
		}
	}()
}

func (rl *IPRateLimiter) GetVisitor(ip string) *Visitor {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	visitor, ok := rl.ips[ip]
	if !ok {
		visitor = &Visitor{
			limiter:  rate.NewLimiter(rl.r, rl.b),
			lastSeen: now,
		}
		rl.ips[ip] = visitor
		return visitor
	}
	visitor.lastSeen = now
	return visitor
}

func RateLimiter(lim *IPRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		visitor := lim.GetVisitor(c.ClientIP())
		if !visitor.limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limited"})
			c.Abort()
			return
		}
		c.Next()
	}
}
