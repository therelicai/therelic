package mediation

import (
	"context"
)

// MCPBinding is a TransportBinding adapter for the MCP stdio protocol.
// The actual proxying is still handled by proxy.MCPProxy; this binding
// provides the interface so the mediation engine can treat MCP as one of
// many pluggable transports.
type MCPBinding struct {
	name string
}

func NewMCPBinding(name string) *MCPBinding {
	return &MCPBinding{name: name}
}

func (b *MCPBinding) Name() string { return b.name }

func (b *MCPBinding) Serve(_ context.Context, _ *MediationEngine) error {
	return nil
}

func (b *MCPBinding) Close() error { return nil }
