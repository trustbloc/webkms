/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import "io"

var _ Handler = (*CmdHandler)(nil)

// Exec is a command execution function type.
type Exec func(rw io.Writer, req io.Reader) error

// Handler for each controller command.
type Handler interface {
	// Method returns a name of the command.
	Method() string
	// Handle executes function of the command.
	Handle() Exec
}

// NewCmdHandler returns instance of CmdHandler which can be used handle
// controller commands.
func NewCmdHandler(method string, exec Exec) *CmdHandler {
	return &CmdHandler{method: method, handle: exec}
}

// CmdHandler contains command handling details which can be used to build controller
// commands.
type CmdHandler struct {
	method string
	handle Exec
}

// Method name of the command.
func (c *CmdHandler) Method() string {
	return c.method
}

// Handle returns execute function of the command handler.
func (c *CmdHandler) Handle() Exec {
	return c.handle
}
