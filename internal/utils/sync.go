package utils

import (
	"sync"
	"time"
)

// Locked holds a value that is written and read by different goroutines.
type Locked[T any] struct {
	mu sync.RWMutex
	v  T
}

func (l *Locked[T]) Load() T {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.v
}

func (l *Locked[T]) Store(v T) {
	l.mu.Lock()
	l.v = v
	l.mu.Unlock()
}

// Go runs f in a new goroutine tracked by wg.
func Go(wg *sync.WaitGroup, f func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		f()
	}()
}

// WaitTimeout waits for wg and reports whether it finished before the timeout.
func WaitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}
