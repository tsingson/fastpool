package pool

import (
    "crypto/tls"
    "io"
    "net"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/tsingson/fastpool/iplimit"
    "github.com/tsingson/fastpool/logger"
    "github.com/tsingson/fastpool/workerpool"
)

// Server implements HTTP server.
//
// Default Server settings should satisfy the majority of Server users.
// Adjust Server settings only if you really understand the consequences.
//
// It is forbidden copying Server instances. Create new Server instances
// instead.
//
// It is safe to call Server methods from concurrently running goroutines.
type Server struct {
	// Handler for processing incoming requests.
	//
	// Take into account that no `panic` recovery is done by `fasthttp` (thus any `panic` will take down the entire server).
	// Instead the user should use `recover` to handle these situations.
	Handler RequestHandler

	// ErrorHandler for returning a response in case of an error while receiving or parsing the request.
	//
	// The following is a non-exhaustive list of errors that can be expected as argument:
	//   * io.EOF
	//   * io.ErrUnexpectedEOF
	//   * ErrGetOnly
	//   * ErrSmallBuffer
	//   * ErrBodyTooLarge
	//   * ErrBrokenChunks
	ErrorHandler func(ctx *RequestCtx, err error)

	// Server name for sending in response headers.
	//
	// Default server name is used if left blank.
	Name string

	// The maximum number of concurrent connections the server may serve.
	//
	// DefaultConcurrency is used if not set.
	Concurrency int

	// Whether to disable keep-alive connections.
	//
	// The server will close all the incoming connections after sending
	// the first response to client if this option is set to true.
	//
	// By default keep-alive connections are enabled.
	DisableKeepalive bool

	// Per-connection buffer size for requests' reading.
	// This also limits the maximum header size.
	//
	// Increase this buffer if your clients send multi-KB RequestURIs
	// and/or multi-KB headers (for example, BIG cookies).
	//
	// Default buffer size is used if not set.
	ReadBufferSize int

	// Per-connection buffer size for responses' writing.
	//
	// Default buffer size is used if not set.
	WriteBufferSize int

	// ReadTimeout is the amount of time allowed to read
	// the full request including body. The connection's read
	// deadline is reset when the connection opens, or for
	// keep-alive connections after the first byte has been read.
	//
	// By default request read timeout is unlimited.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out
	// writes of the response. It is reset after the request handler
	// has returned.
	//
	// By default response write timeout is unlimited.
	WriteTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alive is enabled. If IdleTimeout
	// is zero, the value of ReadTimeout is used.
	IdleTimeout time.Duration

	// Maximum number of concurrent client connections allowed per IP.
	//
	// By default unlimited number of concurrent connections
	// may be established to the server from a single IP address.
	MaxConnsPerIP int

	// Maximum number of requests served per connection.
	//
	// The server closes connection after the last request.
	// 'Connection: close' header is added to the last response.
	//
	// By default unlimited number of requests may be served per connection.
	MaxRequestsPerConn int

	// MaxKeepaliveDuration is a no-op and only left here for backwards compatibility.
	// Deprecated: Use IdleTimeout instead.
	MaxKeepaliveDuration time.Duration

	// Whether to enable tcp keep-alive connections.
	//
	// Whether the operating system should send tcp keep-alive messages on the tcp connection.
	//
	// By default tcp keep-alive connections are disabled.
	TCPKeepalive bool

	// Period between tcp keep-alive messages.
	//
	// TCP keep-alive period is determined by operation system by default.
	TCPKeepalivePeriod time.Duration

	// Maximum request body size.
	//
	// The server rejects requests with bodies exceeding this limit.
	//
	// Request body size is limited by DefaultMaxRequestBodySize by default.
	MaxRequestBodySize int

	// Aggressively reduces memory usage at the cost of higher CPU usage
	// if set to true.
	//
	// Try enabling this option only if the server consumes too much memory
	// serving mostly idle keep-alive connections. This may reduce memory
	// usage by more than 50%.
	//
	// Aggressive memory usage reduction is disabled by default.
	ReduceMemoryUsage bool

	// Rejects all non-GET requests if set to true.
	//
	// This option is useful as anti-DoS protection for servers
	// accepting only GET requests. The request size is limited
	// by ReadBufferSize if GetOnly is set.
	//
	// Server accepts all the requests by default.
	GetOnly bool

	// Logs all errors, including the most frequent
	// 'connection reset by peer', 'broken pipe' and 'connection timeout'
	// errors. Such errors are common in production serving real-world
	// clients.
	//
	// By default the most frequent errors such as
	// 'connection reset by peer', 'broken pipe' and 'connection timeout'
	// are suppressed in order to limit output log traffic.
	LogAllErrors bool

	// Header names are passed as-is without normalization
	// if this option is set.
	//
	// Disabled header names' normalization may be useful only for proxying
	// incoming requests to other servers expecting case-sensitive
	// header names. See https://github.com/valyala/fasthttp/issues/57
	// for details.
	//
	// By default request and response header names are normalized, i.e.
	// The first letter and the first letters following dashes
	// are uppercased, while all the other letters are lowercased.
	// Examples:
	//
	//     * HOST -> Host
	//     * content-type -> Content-Type
	//     * cONTENT-lenGTH -> Content-Length
	DisableHeaderNamesNormalizing bool

	// SleepWhenConcurrencyLimitsExceeded is a duration to be slept of if
	// the concurrency limit in exceeded (default [when is 0]: don't sleep
	// and accept new connections immidiatelly).
	SleepWhenConcurrencyLimitsExceeded time.Duration

	// NoDefaultServerHeader, when set to true, causes the default Server header
	// to be excluded from the Response.
	//
	// The default Server header value is the value of the Name field or an
	// internal default value in its absence. With this option set to true,
	// the only time a Server header will be sent is if a non-zero length
	// value is explicitly provided during a request.
	NoDefaultServerHeader bool

	// NoDefaultContentType, when set to true, causes the default Content-Type
	// header to be excluded from the Response.
	//
	// The default Content-Type header value is the internal default value. When
	// set to true, the Content-Type will not be present.
	NoDefaultContentType bool

	// ConnState specifies an optional callback function that is
	// called when a client connection changes state. See the
	// ConnState type and associated constants for details.
	ConnState func(net.Conn, workerpool.ConnState)

	// Logger, which is used by RequestCtx.Logger().
	//
	// By default standard logger from log package is used.
	Logger logger.Logger

	// KeepHijackedConns is an opt-in disable of connection
	// close by fasthttp after connections' HijackHandler returns.
	// This allows to save goroutines, e.g. when fasthttp used to upgrade
	// http connections to WS and connection goes to another handler,
	// which will close it when needed.
	KeepHijackedConns bool

	tlsConfig  *tls.Config
	nextProtos map[string]workerpool.ServeHandler

	concurrency      uint32
	concurrencyCh    chan struct{}
	perIPConnCounter iplimit.PerIPConnCounter
	serverName       atomic.Value

	ctxPool        sync.Pool
	readerPool     sync.Pool
	writerPool     sync.Pool
	hijackConnPool sync.Pool

	// We need to know our listener so we can close it in Shutdown().
	ln net.Listener

	mu   sync.Mutex
	open int32
	stop int32
	done chan struct{}
}


// Serve serves incoming connections from the given listener.
//
// Serve blocks until the given listener returns permanent error.
func (s *Server) Serve(ln net.Listener) error {
	var lastOverflowErrorTime time.Time
	var lastPerIPErrorTime time.Time
	var c net.Conn
	var err error

	s.mu.Lock()
	{
		if s.ln != nil {
			s.mu.Unlock()
			return ErrAlreadyServing
		}

		s.ln = ln
		s.done = make(chan struct{})
	}
	s.mu.Unlock()

	maxWorkersCount := s.getConcurrency()
	s.concurrencyCh = make(chan struct{}, maxWorkersCount)
	wp := &workerpool.WorkerPool{
		WorkerFunc:      s.serveConn,
		MaxWorkersCount: maxWorkersCount,
		LogAllErrors:    s.LogAllErrors,
		// Logger:          s.logger(),
		ConnState: s.setState,
	}
	wp.Start()

	// Count our waiting to accept a connection as an open connection.
	// This way we can't get into any weird state where just after accepting
	// a connection Shutdown is called which reads open as 0 because it isn't
	// incremented yet.
	atomic.AddInt32(&s.open, 1)
	defer atomic.AddInt32(&s.open, -1)

	for {
		if c, err = acceptConn(s, ln, &lastPerIPErrorTime); err != nil {
			wp.Stop()
			if err == io.EOF {
				return nil
			}
			return err
		}
		s.setState(c, workerpool.StateNew)
		atomic.AddInt32(&s.open, 1)
		if !wp.Serve(c) {
			atomic.AddInt32(&s.open, -1)
			// s.writeFastError(c, StatusServiceUnavailable,
			// 	"The connection cannot be served because Server.Concurrency limit exceeded")
			c.Close()
			s.setState(c, workerpool.StateClosed)
			if time.Since(lastOverflowErrorTime) > time.Minute {
				s.logger().Printf("The incoming connection cannot be served, because %d concurrent connections are served. "+
					"Try increasing Server.Concurrency", maxWorkersCount)
				lastOverflowErrorTime = time.Now()
			}

			// The current server reached concurrency limit,
			// so give other concurrently running servers a chance
			// accepting incoming connections on the same address.
			//
			// There is a hope other servers didn't reach their
			// concurrency limits yet :)
			//
			// See also: https://github.com/valyala/fasthttp/pull/485#discussion_r239994990
			if s.SleepWhenConcurrencyLimitsExceeded > 0 {
				time.Sleep(s.SleepWhenConcurrencyLimitsExceeded)
			}
		}
		c = nil
	}
}

// Shutdown gracefully shuts down the server without interrupting any active connections.
// Shutdown works by first closing all open listeners and then waiting indefinitely for all connections to return to idle and then shut down.
//
// When Shutdown is called, Serve, ListenAndServe, and ListenAndServeTLS immediately return nil.
// Make sure the program doesn't exit and waits instead for Shutdown to return.
//
// Shutdown does not close keepalive connections so its recommended to set ReadTimeout to something else than 0.
func (s *Server) Shutdown() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	atomic.StoreInt32(&s.stop, 1)
	defer atomic.StoreInt32(&s.stop, 0)

	if s.ln == nil {
		return nil
	}

	if err := s.ln.Close(); err != nil {
		return err
	}

	if s.done != nil {
		close(s.done)
	}

	// Closing the listener will make Serve() call Stop on the worker pool.
	// Setting .stop to 1 will make serveConn() break out of its loop.
	// Now we just have to wait until all workers are done.
	for {
		if open := atomic.LoadInt32(&s.open); open == 0 {
			break
		}
		// This is not an optimal solution but using a sync.WaitGroup
		// here causes data races as it's hard to prevent Add() to be called
		// while Wait() is waiting.
		time.Sleep(time.Millisecond * 100)
	}

	s.ln = nil
	return nil
}


func (s *Server) serveConn(c net.Conn) error {
	defer atomic.AddInt32(&s.open, -1)

	connRequestNum := uint64(0)
	// connID := nextConnID()
	// connTime := time.Now()
	maxRequestBodySize := s.MaxRequestBodySize
	if maxRequestBodySize <= 0 {
		maxRequestBodySize = DefaultMaxRequestBodySize
	}

	for {
		connRequestNum++

		// If this is a keep-alive connection set the idle timeout.
		if connRequestNum > 1 {
			if d := s.idleTimeout(); d > 0 {
				// if err := c.SetReadDeadline(time.Now().Add(d)); err != nil {
				//     panic(fmt.Sprintf("BUG: error in SetReadDeadline(%s): %s", d, err))
				// }
			}
		}

		// go hijackConnHandler(hjr, c, s, hijackHandler)

		break
	}

	return nil
}


func acceptConn(s *Server, ln net.Listener, lastPerIPErrorTime *time.Time) (net.Conn, error) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if c != nil {
				panic("BUG: net.Listener returned non-nil conn and non-nil error")
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				s.logger().Printf("Temporary error when accepting new connections: %s", netErr)
				time.Sleep(time.Second)
				continue
			}
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				s.logger().Printf("Permanent error when accepting new connections: %s", err)
				return nil, err
			}
			return nil, io.EOF
		}
		if c == nil {
			panic("BUG: net.Listener returned (nil, nil)")
		}
		if s.MaxConnsPerIP > 0 {
			pic := wrapPerIPConn(s, c)
			if pic == nil {
				if time.Since(*lastPerIPErrorTime) > time.Minute {
					s.logger().Printf("The number of connections from %s exceeds MaxConnsPerIP=%d",
						iplimit.GetConnIP4(c), s.MaxConnsPerIP)
					*lastPerIPErrorTime = time.Now()
				}
				continue
			}
			c = pic
		}
		return c, nil
	}
}

