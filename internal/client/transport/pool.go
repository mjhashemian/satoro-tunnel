package transport

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// maintainPool fills the tunnel pool and resizes it every 10 seconds based on
// how many tunnels the server requested versus how many sat idle.
//
// poolConnections counts idle pooled tunnels, loadConnections counts tunnel requests
// since the last check. Shrinking works by pushing tokens into controlFlow, which makes
// the control channel handler skip that many upcoming tunnel requests.
func maintainPool(ctx context.Context, logger *logrus.Logger, poolSize int, aggressive bool, poolConnections, loadConnections *int32, controlFlow chan struct{}, dial func()) {
	for i := 0; i < poolSize; i++ { //initial pool filling
		go dial()
	}

	// factors
	a := 4
	b := 5
	x := 3
	y := 4.0

	if aggressive {
		logger.Info("aggressive pool management enabled")
		a = 1
		b = 2
		x = 0
		y = 0.75
	}

	tickerPool := time.NewTicker(time.Second * 1)
	defer tickerPool.Stop()

	tickerLoad := time.NewTicker(time.Second * 10)
	defer tickerLoad.Stop()

	newPoolSize := poolSize // intial value
	poolConnectionsSum := 0

	for {
		select {
		case <-ctx.Done():
			return

		case <-tickerPool.C:
			// Accumulate pool connections over time (every second)
			poolConnectionsSum += int(atomic.LoadInt32(poolConnections))

		case <-tickerLoad.C:
			// Calculate the loadConnections over the last 10 seconds
			loadConns := (int(atomic.SwapInt32(loadConnections, 0)) + 9) / 10 // +9 for ceil-like logic

			// Calculate the average pool connections over the last 10 seconds
			poolConnectionsAvg := (poolConnectionsSum + 9) / 10 // +9 for ceil-like logic
			poolConnectionsSum = 0

			// Dynamically adjust the pool size based on current connections
			if (loadConns + a) > poolConnectionsAvg*b {
				logger.Debugf("increasing pool size: %d -> %d, avg pool conn: %d, avg load conn: %d", newPoolSize, newPoolSize+1, poolConnectionsAvg, loadConns)
				newPoolSize++

				// Add a new connection to the pool
				go dial()
			} else if float64(loadConns+x) < float64(poolConnectionsAvg)*y && newPoolSize > poolSize {
				logger.Debugf("decreasing pool size: %d -> %d, avg pool conn: %d, avg load conn: %d", newPoolSize, newPoolSize-1, poolConnectionsAvg, loadConns)
				newPoolSize--

				// send a signal to controlFlow
				select {
				case controlFlow <- struct{}{}:
				default:
				}
			}
		}
	}
}
