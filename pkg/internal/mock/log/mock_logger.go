/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"fmt"

	"github.com/trustbloc/edge-core/pkg/log"
)

type MockLogger struct {
	ErrorText string
	log.Log
}

func (l *MockLogger) Errorf(msg string, args ...interface{}) {
	l.ErrorText = fmt.Sprintf(msg, args...)
}
