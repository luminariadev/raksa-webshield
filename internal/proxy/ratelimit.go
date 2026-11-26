package proxy

import (
	"container/list"
	"math"
	"sync"
	"time"
)

type rateBucket struct {
	key     string
	count   int
	resetAt time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	maxReq  int
	window  time.Duration
	maxKeys int
	order   *list.List
	items   map[string]*list.Element
}

func NewRateLimiter(maxReq int, window time.Duration, maxKeys int) *RateLimiter {
	if maxReq <= 0 {
		maxReq = 120
	}
	if window <= 0 {
		window = 60 * time.Second
	}
	if maxKeys <= 0 {
		maxKeys = 10_000
	}
	return &RateLimiter{
		maxReq:  maxReq,
		window:  window,
		maxKeys: maxKeys,
		order:   list.New(),
		items:   make(map[string]*list.Element),
	}
}

func (rl *RateLimiter) Allow(key string) (allowed bool, retryAfterSec int) {
	return rl.AllowAt(key, time.Now())
}

func (rl *RateLimiter) AllowAt(key string, now time.Time) (allowed bool, retryAfterSec int) {
	if key == "" {
		key = "global"
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if elem, ok := rl.items[key]; ok {
		rl.order.MoveToBack(elem)
		b := elem.Value.(*rateBucket)
		if !now.Before(b.resetAt) {
			b.count = 0
			b.resetAt = now.Add(rl.window)
		}
		b.count++
		if b.count <= rl.maxReq {
			return true, 0
		}
		rem := b.resetAt.Sub(now)
		sec := int(math.Ceil(rem.Seconds()))
		if sec < 1 {
			sec = 1
		}
		return false, sec
	}

	for rl.order.Len() >= rl.maxKeys {
		front := rl.order.Front()
		if front == nil {
			break
		}
		evicted := rl.order.Remove(front).(*rateBucket)
		delete(rl.items, evicted.key)
	}

	b := &rateBucket{
		key:     key,
		count:   1,
		resetAt: now.Add(rl.window),
	}
	elem := rl.order.PushBack(b)
	rl.items[key] = elem
	return true, 0
}

func (rl *RateLimiter) Size() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.order.Len()
}
