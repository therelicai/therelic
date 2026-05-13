package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Streamer is the runtime's optional live-feed flush path. When the
// runtime is configured with RELIC_API_URL + RELIC_API_KEY, the proxy's
// onIntent and onAction callbacks enqueue the sealed event line here;
// a background worker POSTs each enqueued event to the platform's
// /v1/intents endpoint as a single NDJSON line.
//
// Properties this design preserves:
//
//   - Hot path stays local. Submit() never blocks the proxy. If the
//     queue is full, the event is dropped (with a one-time warning) and
//     the durable .trtrace upload at end-of-run is the recovery path.
//
//   - Standalone mode is unchanged. NewStreamerFromEnv returns (nil,
//     nil) when the env gating is unset; callers must nil-check before
//     calling Submit.
//
//   - Streaming failures never affect enforcement. The proxy decides
//     verdicts regardless of network state.
//
// The wire format is the same sealed NDJSON line the runtime writes to
// .trtrace. The platform's /v1/intents handler parses the line's "t"
// field and routes "intent" / "action" events into the live feed.
type Streamer struct {
	baseURL string
	apiKey  string
	http    *http.Client

	queue   chan []byte
	wg      sync.WaitGroup
	once    sync.Once
	stopCh  chan struct{}
	stopped atomic.Bool
	dropped atomic.Uint64
	warnOnce sync.Once
}

// queueDepth caps the in-flight events the streamer will hold for the
// worker. 256 is generous for human-rate agent traffic (~200 calls/min
// would be steady-state) and small enough that a stalled network
// doesn't balloon process memory. Drops on overflow are intentional:
// the durable batch path catches every event eventually.
const queueDepth = 256

// flushTimeout caps a single POST so a slow platform doesn't pin the
// worker goroutine. 2s aligns with the slice 14 acceptance test's "2
// seconds end-to-end" budget; if a flush misses this, the event is
// dropped and surfaced via the dropped counter.
const flushTimeout = 2 * time.Second

// NewStreamerFromEnv constructs a Streamer when RELIC_API_URL +
// RELIC_API_KEY are both set. Otherwise returns (nil, nil) — the
// caller must treat a nil Streamer as "streaming disabled" and skip
// Submit calls. This matches the existing standalone-mode contract:
// no env vars set means no network traffic.
func NewStreamerFromEnv() (*Streamer, error) {
	key := os.Getenv(EnvAPIKey)
	base := os.Getenv(EnvBaseURL)
	if key == "" || base == "" {
		return nil, nil
	}
	s := &Streamer{
		baseURL: base,
		apiKey:  key,
		http:    &http.Client{Timeout: flushTimeout},
		queue:   make(chan []byte, queueDepth),
		stopCh:  make(chan struct{}),
	}
	s.wg.Add(1)
	go s.run()
	return s, nil
}

// Submit enqueues a sealed event line for delivery. The line must
// already include the trailing "hmac" field when the runtime is
// emitting a sealed chain — the streamer doesn't reseal. Returns
// false if the streamer is stopped or the queue is full.
//
// Submit MUST NOT block the proxy's hot path. The select-default
// makes "queue full" an immediate drop rather than a stall.
func (s *Streamer) Submit(sealedLine []byte) bool {
	if s == nil || s.stopped.Load() {
		return false
	}
	// Copy: the caller's buffer is owned by the trace writer and may
	// be reused on the next emission.
	cp := make([]byte, len(sealedLine))
	copy(cp, sealedLine)
	select {
	case s.queue <- cp:
		return true
	default:
		s.dropped.Add(1)
		s.warnOnce.Do(func() {
			fmt.Fprintln(os.Stderr,
				"relic: streaming queue full; events dropped from live feed (batch upload at end-of-run remains durable)")
		})
		return false
	}
}

// Close stops the worker. Safe to call multiple times. Pending events
// in the queue are abandoned — the batch trace push at end-of-run
// uploads them anyway.
func (s *Streamer) Close() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		s.stopped.Store(true)
		close(s.stopCh)
	})
	s.wg.Wait()
}

// Dropped reports how many events were dropped due to queue overflow.
// Exposed for tests and observability.
func (s *Streamer) Dropped() uint64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

func (s *Streamer) run() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stopCh:
			return
		case line := <-s.queue:
			s.flush(line)
		}
	}
}

// flush POSTs a single sealed event line. Errors are logged once via
// the dropped counter; we don't retry within the streamer because the
// .trtrace file already contains every event and `relic trace push`
// is the durable backfill.
func (s *Streamer) flush(line []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/intents", bytes.NewReader(line))
	if err != nil {
		s.dropped.Add(1)
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := s.http.Do(req)
	if err != nil {
		s.dropped.Add(1)
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode/100 != 2 {
		s.dropped.Add(1)
	}
}
