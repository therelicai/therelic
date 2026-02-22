package mediation

import (
	"context"
)

// HTTPBinding is a TransportBinding adapter for HTTP/HTTPS traffic.
// Like MCPBinding, the actual HTTP interception remains in proxy.HTTPLogger;
// this provides the pluggable-transport interface.
type HTTPBinding struct {
	name string
}

func NewHTTPBinding(name string) *HTTPBinding {
	return &HTTPBinding{name: name}
}

func (b *HTTPBinding) Name() string { return b.name }

func (b *HTTPBinding) Serve(_ context.Context, _ *MediationEngine) error {
	return nil
}

func (b *HTTPBinding) Close() error { return nil }
