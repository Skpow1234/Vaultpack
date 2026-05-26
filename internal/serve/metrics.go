package serve

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics holds the Prometheus-style counters and histograms emitted by
// the server at /metrics. We hand-roll the exposition format (text 0.0.4)
// to avoid pulling in github.com/prometheus/client_golang — the metric
// set is small and the format is stable.
type Metrics struct {
	startedAt time.Time

	requestsMu     sync.Mutex
	requestsTotal  map[requestLabels]uint64
	requestSecsMu  sync.Mutex
	requestSecHist map[string]*latencyHistogram

	AuthDenied atomic.Uint64

	kmsRef *KMSCache // set by the server so cache stats can be exposed
}

type requestLabels struct {
	Path   string
	Status int
}

// histogramBuckets are the standard Prometheus le bounds (seconds).
var histogramBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

type latencyHistogram struct {
	counts []uint64 // same length as histogramBuckets+1 (+Inf bucket)
	sum    float64
	count  uint64
}

func newLatencyHistogram() *latencyHistogram {
	return &latencyHistogram{counts: make([]uint64, len(histogramBuckets)+1)}
}

func (h *latencyHistogram) observe(secs float64) {
	for i, b := range histogramBuckets {
		if secs <= b {
			h.counts[i]++
		}
	}
	h.counts[len(histogramBuckets)]++ // +Inf
	h.sum += secs
	h.count++
}

// NewMetrics returns a Metrics with zero-valued counters.
func NewMetrics() *Metrics {
	return &Metrics{
		startedAt:      time.Now(),
		requestsTotal:  make(map[requestLabels]uint64),
		requestSecHist: make(map[string]*latencyHistogram),
	}
}

// AttachKMSCache wires in the cache so /metrics can publish hit/miss stats.
func (m *Metrics) AttachKMSCache(c *KMSCache) { m.kmsRef = c }

func (m *Metrics) observe(path string, status int, d time.Duration) {
	m.requestsMu.Lock()
	m.requestsTotal[requestLabels{Path: path, Status: status}]++
	m.requestsMu.Unlock()

	m.requestSecsMu.Lock()
	h, ok := m.requestSecHist[path]
	if !ok {
		h = newLatencyHistogram()
		m.requestSecHist[path] = h
	}
	h.observe(d.Seconds())
	m.requestSecsMu.Unlock()
}

// ServeHTTP renders the Prometheus text exposition format at /metrics.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	m.write(w)
}

func (m *Metrics) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP vaultpack_build_info Build info; the constant 1 with a version label.\n")
	fmt.Fprintf(w, "# TYPE vaultpack_build_info gauge\n")
	fmt.Fprintf(w, "vaultpack_build_info{version=%q} 1\n", "0.1.0")

	fmt.Fprintf(w, "# HELP vaultpack_uptime_seconds Server uptime in seconds.\n")
	fmt.Fprintf(w, "# TYPE vaultpack_uptime_seconds counter\n")
	fmt.Fprintf(w, "vaultpack_uptime_seconds %g\n", time.Since(m.startedAt).Seconds())

	fmt.Fprintf(w, "# HELP vaultpack_auth_denied_total Requests rejected by the auth gate.\n")
	fmt.Fprintf(w, "# TYPE vaultpack_auth_denied_total counter\n")
	fmt.Fprintf(w, "vaultpack_auth_denied_total %d\n", m.AuthDenied.Load())

	m.writeRequestsTotal(w)
	m.writeLatencyHistograms(w)
	m.writeKMSCache(w)
}

func (m *Metrics) writeRequestsTotal(w io.Writer) {
	m.requestsMu.Lock()
	snapshot := make(map[requestLabels]uint64, len(m.requestsTotal))
	for k, v := range m.requestsTotal {
		snapshot[k] = v
	}
	m.requestsMu.Unlock()

	fmt.Fprintf(w, "# HELP vaultpack_http_requests_total Total HTTP requests served, labelled by path and status.\n")
	fmt.Fprintf(w, "# TYPE vaultpack_http_requests_total counter\n")

	// Deterministic ordering for diffability + tests.
	keys := make([]requestLabels, 0, len(snapshot))
	for k := range snapshot {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Path != keys[j].Path {
			return keys[i].Path < keys[j].Path
		}
		return keys[i].Status < keys[j].Status
	})
	for _, k := range keys {
		fmt.Fprintf(w, "vaultpack_http_requests_total{path=%q,status=\"%d\"} %d\n",
			k.Path, k.Status, snapshot[k])
	}
}

func (m *Metrics) writeLatencyHistograms(w io.Writer) {
	m.requestSecsMu.Lock()
	paths := make([]string, 0, len(m.requestSecHist))
	for p := range m.requestSecHist {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	m.requestSecsMu.Unlock()

	fmt.Fprintf(w, "# HELP vaultpack_http_request_duration_seconds Request latency in seconds, per path.\n")
	fmt.Fprintf(w, "# TYPE vaultpack_http_request_duration_seconds histogram\n")
	for _, p := range paths {
		m.requestSecsMu.Lock()
		h := m.requestSecHist[p]
		counts := append([]uint64(nil), h.counts...)
		sum := h.sum
		count := h.count
		m.requestSecsMu.Unlock()
		for i, b := range histogramBuckets {
			fmt.Fprintf(w, "vaultpack_http_request_duration_seconds_bucket{path=%q,le=\"%s\"} %d\n",
				p, formatBucket(b), counts[i])
		}
		fmt.Fprintf(w, "vaultpack_http_request_duration_seconds_bucket{path=%q,le=\"+Inf\"} %d\n",
			p, counts[len(histogramBuckets)])
		fmt.Fprintf(w, "vaultpack_http_request_duration_seconds_sum{path=%q} %g\n", p, sum)
		fmt.Fprintf(w, "vaultpack_http_request_duration_seconds_count{path=%q} %d\n", p, count)
	}
}

func formatBucket(b float64) string {
	// Prometheus accepts decimal numbers; trim trailing zeros for readability.
	s := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", b), "0"), ".")
	if s == "" {
		s = "0"
	}
	return s
}

func (m *Metrics) writeKMSCache(w io.Writer) {
	if m.kmsRef == nil {
		return
	}
	stats := m.kmsRef.Stats()
	fmt.Fprintf(w, "# HELP vaultpack_kms_cache_entries Current KMS unwrap cache size.\n")
	fmt.Fprintf(w, "# TYPE vaultpack_kms_cache_entries gauge\n")
	fmt.Fprintf(w, "vaultpack_kms_cache_entries %d\n", stats.Size)
	fmt.Fprintf(w, "# HELP vaultpack_kms_cache_hits_total KMS unwrap cache hits.\n")
	fmt.Fprintf(w, "# TYPE vaultpack_kms_cache_hits_total counter\n")
	fmt.Fprintf(w, "vaultpack_kms_cache_hits_total %d\n", stats.Hits)
	fmt.Fprintf(w, "# HELP vaultpack_kms_cache_misses_total KMS unwrap cache misses.\n")
	fmt.Fprintf(w, "# TYPE vaultpack_kms_cache_misses_total counter\n")
	fmt.Fprintf(w, "vaultpack_kms_cache_misses_total %d\n", stats.Misses)
	fmt.Fprintf(w, "# HELP vaultpack_kms_cache_evicted_total KMS unwrap cache evictions.\n")
	fmt.Fprintf(w, "# TYPE vaultpack_kms_cache_evicted_total counter\n")
	fmt.Fprintf(w, "vaultpack_kms_cache_evicted_total %d\n", stats.Evicted)
}
