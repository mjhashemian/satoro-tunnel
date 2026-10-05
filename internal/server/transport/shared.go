package transport

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
)

// udpFlowQueueSize is how many packets each UDP flow can queue before new ones are dropped.
// The queue is allocated per client address, so it is kept modest (~100 KB per flow).
const udpFlowQueueSize = 4096

type TunnelChannel struct { // for websocket
	conn *websocket.Conn
	ping chan struct{}
	mu   *sync.Mutex
}

type LocalTCPConn struct {
	conn        net.Conn
	remoteAddr  string
	timeCreated int64
}

type LocalAcceptUDPConn struct {
	timeCreated int64
	payload     chan []byte
	remoteAddr  string
	listener    *net.UDPConn
	clientAddr  *net.UDPAddr
	IsCongested atomic.Bool // for congested tcp connection
}

type LocalUDPConn struct {
	timeCreated int64
	payload     chan []byte
	remoteAddr  string
	listener    *net.UDPConn
	addr        *net.UDPAddr
}

type TunnelUDPConn struct {
	timeCreated int64
	payload     chan []byte
	addr        *net.UDPAddr
	listener    *net.UDPConn
	ping        chan struct{}
	mu          *sync.Mutex //mutex for ping channel
}
