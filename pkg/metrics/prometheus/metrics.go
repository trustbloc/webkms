/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prometheus

import (
	"sync"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace                 = "kms"
	resolveKeystoreTimeMetric = "resolve_keystore_seconds"
)

var logger = log.New("metrics/prometheus") //nolint:gochecknoglobals // ignore

//nolint:gochecknoglobals // ignore
var (
	once            sync.Once
	metricsInstance *Metrics
)

// Metrics manages Prometheus metrics for KMS.
type Metrics struct {
	resolveKeystoreTime prometheus.Histogram
}

// GetMetrics returns an instance of Prometheus metrics provider for KMS.
func GetMetrics() *Metrics {
	once.Do(func() {
		metricsInstance = &Metrics{
			resolveKeystoreTime: newResolveKeystoreTime(),
		}
	})

	return metricsInstance
}

// ResolveKeystoreTime records the time it takes to resolve a keystore.
func (m *Metrics) ResolveKeystoreTime(value time.Duration) {
	m.resolveKeystoreTime.Observe(value.Seconds())
}

func newResolveKeystoreTime() prometheus.Histogram {
	h := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      resolveKeystoreTimeMetric,
		Help:      "The time (in seconds) that it takes to resolve a keystore.",
	})

	prometheus.MustRegister(h)

	return h
}
