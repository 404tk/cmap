package options

import (
	"time"
)

type Options struct {
	Agents  []string
	Query   interface{}
	Timeout int // default 30s
	// Note these ratelimits are used as fallback in case agent
	// ratelimit is not available in DefaultRateLimits
	RateLimit     uint          // default 30 req
	RateLimitUnit time.Duration // default unit
}
