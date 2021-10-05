/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prometheus

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	requestCounterMetric        = "http_requests_count"
	responseLatencyMetric       = "http_response_seconds"
	responseStatusCounterMetric = "http_response_status_count"
)

//nolint:gochecknoglobals // ignore
var (
	httpMetricsOnce     sync.Once
	httpMetricsInstance *httpMetrics
)

type httpMetrics struct {
	requestCounter        *prometheus.CounterVec
	responseLatency       *prometheus.HistogramVec
	responseStatusCounter *prometheus.CounterVec
}

// Middleware records Prometheus metrics for HTTP requests.
func Middleware(next http.Handler) http.Handler {
	httpMetricsOnce.Do(func() {
		httpMetricsInstance = &httpMetrics{
			requestCounter:        newRequestCounterMetric(),
			responseLatency:       newResponseLatencyMetric(),
			responseStatusCounter: newResponseStatusCounterMetric(),
		}
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := mux.CurrentRoute(r)
		if route == nil {
			logger.Errorf("Fail to get route for request: %q", r.URL)

			return
		}

		path, err := route.GetPathTemplate()
		if err != nil {
			logger.Errorf("Fail to get route path template: %v", err)

			return
		}

		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		start := time.Now()

		next.ServeHTTP(rw, r)

		httpMetricsInstance.responseLatency.WithLabelValues(path).Observe(time.Since(start).Seconds())
		httpMetricsInstance.requestCounter.WithLabelValues(path).Inc()
		httpMetricsInstance.responseStatusCounter.WithLabelValues(strconv.Itoa(rw.statusCode)).Inc()
	})
}

func newRequestCounterMetric() *prometheus.CounterVec {
	v := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      requestCounterMetric,
		Help:      "The total number of HTTP requests",
	}, []string{"path"})

	prometheus.MustRegister(v)

	return v
}

func newResponseLatencyMetric() *prometheus.HistogramVec {
	v := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      responseLatencyMetric,
		Help:      "The time (in seconds) that it takes to process a request",
	}, []string{"path"})

	prometheus.MustRegister(v)

	return v
}

func newResponseStatusCounterMetric() *prometheus.CounterVec {
	v := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      responseStatusCounterMetric,
		Help:      "The total number of HTTP response statuses",
	}, []string{"status"})

	prometheus.MustRegister(v)

	return v
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
