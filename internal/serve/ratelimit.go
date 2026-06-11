package serve

import (
	"net"
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

type rateLimiter struct {
	rps   rate.Limit
	burst int
	mu    sync.Mutex
	byIP  map[string]*rate.Limiter
}

func newRateLimiter(rps float64, burst int) *rateLimiter {
	if rps <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = int(rps) + 1
	}
	return &rateLimiter{
		rps:   rate.Limit(rps),
		burst: burst,
		byIP:  make(map[string]*rate.Limiter),
	}
}

func (rl *rateLimiter) allow(r *http.Request) bool {
	if rl == nil {
		return true
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	rl.mu.Lock()
	lim, ok := rl.byIP[ip]
	if !ok {
		lim = rate.NewLimiter(rl.rps, rl.burst)
		rl.byIP[ip] = lim
	}
	rl.mu.Unlock()
	return lim.Allow()
}

func (s *Server) rateLimitMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		if s.rateLimit != nil && !s.rateLimit.allow(r) {
			s.metrics.RateLimited.Add(1)
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}
