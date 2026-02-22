package mediation

import "context"

// TransportBinding abstracts a protocol-specific listener (MCP stdio, HTTP,
// SSE, etc.) that feeds action intents into a MediationEngine.
type TransportBinding interface {
	Name() string
	Serve(ctx context.Context, engine *MediationEngine) error
	Close() error
}
