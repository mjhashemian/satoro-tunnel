package handlers

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// copyBufferSize is the size of the pooled buffers used to move data between connections.
const copyBufferSize = 32 * 1024

var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, copyBufferSize)
		return &b
	},
}

func getBuffer() *[]byte  { return bufferPool.Get().(*[]byte) }
func putBuffer(b *[]byte) { bufferPool.Put(b) }

// countingWriter adds the bytes written to counter.
type countingWriter struct {
	w       io.Writer
	counter *atomic.Uint64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.counter.Add(uint64(n))
	}
	return n, err
}

// readerOnly and writerOnly hide ReadFrom/WriteTo, so io.CopyBuffer uses the pooled
// buffer instead of a fallback path that allocates its own.
type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

// copyConn copies from src to dst until EOF or an error, counting bytes into counter
// when it is not nil. It picks the cheapest available path:
//   - TCP to TCP without counting: io.Copy, which uses splice(2) on Linux (no user-space copy)
//   - sources with their own WriteTo (e.g. smux streams): no intermediate buffer
//   - everything else: a pooled buffer
func copyConn(dst, src net.Conn, counter *atomic.Uint64) (int64, error) {
	_, srcTCP := src.(*net.TCPConn)
	_, dstTCP := dst.(*net.TCPConn)

	if counter == nil && srcTCP && dstTCP {
		return io.Copy(dst, src)
	}

	var w io.Writer = dst
	if counter != nil {
		w = &countingWriter{w: dst, counter: counter}
	}

	// *net.TCPConn also implements WriteTo, but its generic fallback allocates a buffer per call
	if wt, ok := src.(io.WriterTo); ok && !srcTCP {
		return wt.WriteTo(w)
	}

	buf := getBuffer()
	defer putBuffer(buf)
	return io.CopyBuffer(writerOnly{w}, readerOnly{src}, *buf)
}
