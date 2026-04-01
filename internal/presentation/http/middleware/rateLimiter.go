package middleware

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type IPRateLimiter struct {
	ips map[string]*rate.Limiter
	mu  *sync.RWMutex
	r   rate.Limit
	b   int
}

func NewIPRateLimiter(rateLimit rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		ips: make(map[string]*rate.Limiter),
		mu:  &sync.RWMutex{},
		r:   rateLimit,
		b:   b,
	}
}

func (rl *IPRateLimiter) AddIP(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.ips[ip] = rate.NewLimiter(rl.r, rl.b)
	return rl.ips[ip]
}

func (rl *IPRateLimiter) DelIP(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.ips, ip)
}
func (rl *IPRateLimiter) GetRL(ip string) *rate.Limiter {
	rl.mu.RLock()
	limiter, ok := rl.ips[ip]
	if !ok {
		rl.mu.RUnlock()
		return rl.AddIP(ip)
	}
	rl.mu.RUnlock()
	return limiter
}

func RateLimiter(lim *IPRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		limiter := lim.GetRL(c.ClientIP())
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, "Rate limit exceeded")
			c.Abort()
			return
		}
		c.Next()
	}
}
