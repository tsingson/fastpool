package pool

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"mime/multipart"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tsingson/fastpool/logger"
	"github.com/tsingson/fastpool/workerpool"
)

var errNoCertOrKeyProvided = errors.New("Cert or key has not provided")

var (
	// ErrAlreadyServing is returned when calling Serve on a Server
	// that is already serving connections.
	ErrAlreadyServing = errors.New("Server is already serving connections")
)

// Request represents HTTP request.
//
// It is forbidden copying Request instances. Create new instances
// and use CopyTo instead.
//
// Request instance MUST NOT be used from concurrently running goroutines.
type Request struct {

	// Request header
	//
	// Copying Header by value is forbidden. Use pointer to Header instead.

	multipartForm         *multipart.Form
	multipartFormBoundary string

	// Group bool members in order to reduce Request object size.
	parsedURI      bool
	parsedPostArgs bool

	keepBodyBuffer bool

	isTLS bool

	// To detect scheme changes in redirects
	schemaUpdate bool
}

// Response represents HTTP response.
//
// It is forbidden copying Response instances. Create new instances
// and use CopyTo instead.
//
// Response instance MUST NOT be used from concurrently running goroutines.
type Response struct {
	bodyRaw []byte

	// Response.Read() skips reading body if set to true.
	// Use it for reading HEAD responses.
	//
	// Response.Write() skips writing body if set to true.
	// Use it for writing HEAD responses.
	SkipBody bool

	keepBodyBuffer bool

	// Remote TCPAddr from concurrently net.Conn
	raddr net.Addr
	// Local TCPAddr from concurrently net.Conn
	laddr net.Addr
}

// RequestCtx contains incoming request and manages outgoing response.
//
// It is forbidden copying RequestCtx instances.
//
// RequestHandler should avoid holding references to incoming RequestCtx and/or
// its' members after the return.
// If holding RequestCtx references after the return is unavoidable
// (for instance, ctx is passed to a separate goroutine and ctx lifetime cannot
// be controlled), then the RequestHandler MUST call ctx.TimeoutError()
// before return.
//
// It is unsafe modifying/reading RequestCtx instance from concurrently
// running goroutines. The only exception is TimeoutError*, which may be called
// while other goroutines accessing RequestCtx.
type RequestCtx struct {

	// Incoming request.
	//
	// Copying Request by value is forbidden. Use pointer to Request instead.
	Request Request

	// Outgoing response.
	//
	// Copying Response by value is forbidden. Use pointer to Response instead.
	Response Response

	connID         uint64
	connRequestNum uint64
	connTime       time.Time

	time time.Time

	logger ctxLogger
	s      *Server
	c      net.Conn
	fbr    firstByteReader

	timeoutCh    chan struct{}
	timeoutTimer *time.Timer

	hijackHandler HijackHandler
}

// ServeConn serves HTTP requests from the given connection
// using the given handler.
//
// ServeConn returns nil if all requests from the c are successfully served.
// It returns non-nil error otherwise.
//
// Connection c must immediately propagate all the data passed to Write()
// to the client. Otherwise requests' processing may hang.
//
// ServeConn closes c before returning.
func ServeConn(c net.Conn, handler RequestHandler) error {
	v := serverPool.Get()
	if v == nil {
		v = &Server{}
	}
	s := v.(*Server)
	s.Handler = handler
	err := s.ServeConn(c)
	s.Handler = nil
	serverPool.Put(v)
	return err
}

var serverPool sync.Pool

// Serve serves incoming connections from the given listener
// using the given handler.
//
// Serve blocks until the given listener returns permanent error.
func Serve(ln net.Listener, handler RequestHandler) error {
	s := &Server{
		Handler: handler,
	}
	return s.Serve(ln)
}

// ListenAndServe serves HTTP requests from the given TCP addr
// using the given handler.
func ListenAndServe(addr string, handler RequestHandler) error {
	s := &Server{
		Handler: handler,
	}
	return s.ListenAndServe(addr)
}

// RequestHandler must process incoming requests.
//
// RequestHandler must call ctx.TimeoutError() before returning
// if it keeps references to ctx and/or its' members after the return.
// Consider wrapping RequestHandler into TimeoutHandler if response time
// must be limited.
type RequestHandler func(ctx *RequestCtx)

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
	perIPConnCounter perIPConnCounter
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

// HijackHandler must process the hijacked connection c.
//
// If KeepHijackedConns is disabled, which is by default,
// the connection c is automatically closed after returning from HijackHandler.
//
// The connection c must not be used after returning from the handler, if KeepHijackedConns is disabled.
//
// When KeepHijackedConns enabled, fasthttp will not Close() the connection,
// you must do it when you need it. You must not use c in any way after calling Close().
type HijackHandler func(c net.Conn)

type connTLSer interface {
	Handshake() error
	ConnectionState() tls.ConnectionState
}

type firstByteReader struct {
	c        net.Conn
	ch       byte
	byteRead bool
}

func (r *firstByteReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	nn := 0
	if !r.byteRead {
		b[0] = r.ch
		b = b[1:]
		r.byteRead = true
		nn = 1
	}
	n, err := r.c.Read(b)
	return n + nn, err
}

var ctxLoggerLock sync.Mutex

type ctxLogger struct {
	ctx    *RequestCtx
	logger logger.Logger
}

var zeroTCPAddr = &net.TCPAddr{
	IP: net.IPv4zero,
}

// ErrMissingFile may be returned from FormFile when the is no uploaded file
// associated with the given multipart form key.
var ErrMissingFile = errors.New("there is no uploaded file associated with the given key")

func addrToIP(addr net.Addr) net.IP {
	x, ok := addr.(*net.TCPAddr)
	if !ok {
		return net.IPv4zero
	}
	return x.IP
}

func getRedirectStatusCode(statusCode int) int {
	if statusCode == StatusMovedPermanently || statusCode == StatusFound ||
		statusCode == StatusSeeOther || statusCode == StatusTemporaryRedirect ||
		statusCode == StatusPermanentRedirect {
		return statusCode
	}
	return StatusFound
}

// NotFound resets response and sets '404 Not Found' response status code.

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe, ListenAndServeTLS and
// ListenAndServeTLSEmbed so dead TCP connections (e.g. closing laptop mid-download)
// eventually go away.
type tcpKeepaliveListener struct {
	*net.TCPListener
	keepalivePeriod time.Duration
}

func (ln tcpKeepaliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	if ln.keepalivePeriod > 0 {
		tc.SetKeepAlivePeriod(ln.keepalivePeriod)
	}
	return tc, nil
}

// ListenAndServe serves HTTP requests from the given TCP4 addr.
//
// Pass custom listener to Serve if you need listening on non-TCP4 media
// such as IPv6.
//
// Accepted connections are configured to enable TCP keep-alives.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	if s.TCPKeepalive {
		if tcpln, ok := ln.(*net.TCPListener); ok {
			return s.Serve(tcpKeepaliveListener{
				TCPListener:     tcpln,
				keepalivePeriod: s.TCPKeepalivePeriod,
			})
		}
	}
	return s.Serve(ln)
}

// DefaultConcurrency is the maximum number of concurrent connections
// the Server may serve by default (i.e. if Server.Concurrency isn't set).
const DefaultConcurrency = 256 * 1024

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
						GetConnIP4(c), s.MaxConnsPerIP)
					*lastPerIPErrorTime = time.Now()
				}
				continue
			}
			c = pic
		}
		return c, nil
	}
}

func wrapPerIPConn(s *Server, c net.Conn) net.Conn {
	ip := getUint32IP(c)
	if ip == 0 {
		return c
	}
	n := s.perIPConnCounter.Register(ip)
	if n > s.MaxConnsPerIP {
		s.perIPConnCounter.Unregister(ip)
		//    s.writeFastError(c, StatusTooManyRequests, "The number of connections from your ip exceeds MaxConnsPerIP")
		c.Close()
		return nil
	}
	return acquirePerIPConn(c, ip, &s.perIPConnCounter)
}

var defaultLogger = logger.Logger(log.New(os.Stderr, "", log.LstdFlags))

func (s *Server) logger() logger.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return defaultLogger
}

var (
	// ErrPerIPConnLimit may be returned from ServeConn if the number of connections
	// per ip exceeds Server.MaxConnsPerIP.
	ErrPerIPConnLimit = errors.New("too many connections per ip")

	// ErrConcurrencyLimit may be returned from ServeConn if the number
	// of concurrently served connections exceeds Server.Concurrency.
	ErrConcurrencyLimit = errors.New("cannot serve the connection because Server.Concurrency concurrent connections are served")
)

// ServeConn serves HTTP requests from the given connection.
//
// ServeConn returns nil if all requests from the c are successfully served.
// It returns non-nil error otherwise.
//
// Connection c must immediately propagate all the data passed to Write()
// to the client. Otherwise requests' processing may hang.
//
// ServeConn closes c before returning.
func (s *Server) ServeConn(c net.Conn) error {
	if s.MaxConnsPerIP > 0 {
		pic := wrapPerIPConn(s, c)
		if pic == nil {
			return ErrPerIPConnLimit
		}
		c = pic
	}

	n := atomic.AddUint32(&s.concurrency, 1)
	if n > uint32(s.getConcurrency()) {
		atomic.AddUint32(&s.concurrency, ^uint32(0))
		// 	s.writeFastError(c, StatusServiceUnavailable, "The connection cannot be served because Server.Concurrency limit exceeded")
		c.Close()
		return ErrConcurrencyLimit
	}

	atomic.AddInt32(&s.open, 1)

	err := s.serveConn(c)

	atomic.AddUint32(&s.concurrency, ^uint32(0))

	if err != workerpool.ErrHijacked {
		err1 := c.Close()
		s.setState(c, workerpool.StateClosed)
		if err == nil {
			err = err1
		}
	} else {
		err = nil
		s.setState(c, workerpool.StateHijacked)
	}
	return err
}

// GetCurrentConcurrency returns a number of currently served
// connections.
//
// This function is intended be used by monitoring systems
func (s *Server) GetCurrentConcurrency() uint32 {
	return atomic.LoadUint32(&s.concurrency)
}

// GetOpenConnectionsCount returns a number of opened connections.
//
// This function is intended be used by monitoring systems
func (s *Server) GetOpenConnectionsCount() int32 {
	return atomic.LoadInt32(&s.open) - 1
}

func (s *Server) getConcurrency() int {
	n := s.Concurrency
	if n <= 0 {
		n = DefaultConcurrency
	}
	return n
}

var globalConnID uint64

func nextConnID() uint64 {
	return atomic.AddUint64(&globalConnID, 1)
}

// DefaultMaxRequestBodySize is the maximum request body size the server
// reads by default.
//
// See Server.MaxRequestBodySize for details.
const DefaultMaxRequestBodySize = 4 * 1024 * 1024

func (s *Server) idleTimeout() time.Duration {
	if s.IdleTimeout != 0 {
		return s.IdleTimeout
	}
	return s.ReadTimeout
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

func (s *Server) setState(nc net.Conn, state workerpool.ConnState) {
	if hook := s.ConnState; hook != nil {
		hook(nc, state)
	}
}

func hijackConnHandler(r io.Reader, c net.Conn, s *Server, h HijackHandler) {
	hjc := s.acquireHijackConn(r, c)
	h(hjc)

	if br, ok := r.(*bufio.Reader); ok {
		releaseReader(s, br)
	}
	if !s.KeepHijackedConns {
		c.Close()
		s.releaseHijackConn(hjc)
	}
}

func (s *Server) acquireHijackConn(r io.Reader, c net.Conn) *hijackConn {
	v := s.hijackConnPool.Get()
	if v == nil {
		hjc := &hijackConn{
			Conn: c,
			r:    r,
			s:    s,
		}
		return hjc
	}
	hjc := v.(*hijackConn)
	hjc.Conn = c
	hjc.r = r
	return hjc
}

func (s *Server) releaseHijackConn(hjc *hijackConn) {
	hjc.Conn = nil
	hjc.r = nil
	s.hijackConnPool.Put(hjc)
}

type hijackConn struct {
	net.Conn
	r io.Reader
	s *Server
}

func (c *hijackConn) UnsafeConn() net.Conn {
	return c.Conn
}

func (c *hijackConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *hijackConn) Close() error {
	if !c.s.KeepHijackedConns {
		// when we do not keep hijacked connections,
		// it is closed in hijackConnHandler.
		return nil
	}

	conn := c.Conn
	c.s.releaseHijackConn(c)
	return conn.Close()
}

const (
	defaultReadBufferSize  = 4096
	defaultWriteBufferSize = 4096
)

func acquireReader(ctx *RequestCtx) *bufio.Reader {
	v := ctx.s.readerPool.Get()
	if v == nil {
		n := ctx.s.ReadBufferSize
		if n <= 0 {
			n = defaultReadBufferSize
		}
		return bufio.NewReaderSize(ctx.c, n)
	}
	r := v.(*bufio.Reader)
	r.Reset(ctx.c)
	return r
}

func releaseReader(s *Server, r *bufio.Reader) {
	s.readerPool.Put(r)
}

func acquireWriter(ctx *RequestCtx) *bufio.Writer {
	v := ctx.s.writerPool.Get()
	if v == nil {
		n := ctx.s.WriteBufferSize
		if n <= 0 {
			n = defaultWriteBufferSize
		}
		return bufio.NewWriterSize(ctx.c, n)
	}
	w := v.(*bufio.Writer)
	w.Reset(ctx.c)
	return w
}

func releaseWriter(s *Server, w *bufio.Writer) {
	s.writerPool.Put(w)
}

var fakeServer = &Server{
	// Initialize concurrencyCh for TimeoutHandler
	concurrencyCh: make(chan struct{}, DefaultConcurrency),
}

type fakeAddrer struct {
	net.Conn
	laddr net.Addr
	raddr net.Addr
}

func (fa *fakeAddrer) RemoteAddr() net.Addr {
	return fa.raddr
}

func (fa *fakeAddrer) LocalAddr() net.Addr {
	return fa.laddr
}

func (fa *fakeAddrer) Read(p []byte) (int, error) {
	panic("BUG: unexpected Read call")
}

func (fa *fakeAddrer) Write(p []byte) (int, error) {
	panic("BUG: unexpected Write call")
}

func (fa *fakeAddrer) Close() error {
	panic("BUG: unexpected Close call")
}
