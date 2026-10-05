package network

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	retryInitialBackoff = 1 * time.Second
	retryMaxBackoff     = 30 * time.Second
)

// RetryListen calls listen until it succeeds or ctx is done, backing off exponentially
// between attempts. It returns false only when ctx is done.
func RetryListen[T any](ctx context.Context, logger *logrus.Logger, desc string, listen func() (T, error)) (T, bool) {
	backoff := retryInitialBackoff

	for {
		l, err := listen()
		if err == nil {
			return l, true
		}

		if ctx.Err() != nil {
			var zero T
			return zero, false
		}

		logger.Errorf("failed to listen on %s: %v, retrying in %v", desc, err, backoff)

		select {
		case <-ctx.Done():
			var zero T
			return zero, false
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > retryMaxBackoff {
			backoff = retryMaxBackoff
		}
	}
}
