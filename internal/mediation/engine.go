package mediation

import (
	"github.com/therelicai/therelic/internal/policy"
	"github.com/therelicai/therelic/internal/trace"
)

// ActionIntent is the transport-agnostic representation of an intercepted
// action before it reaches the policy engine. Transport bindings convert
// their protocol-specific requests into this form.
type ActionIntent struct {
	Protocol string
	Method   string
	Target   string
	Params   interface{}
	Ctx      interface{}
}

// MediationResult pairs a policy AuthDecision with a convenience Allowed flag.
type MediationResult struct {
	Decision policy.AuthDecision
	Allowed  bool
}

// TraceEmitter is satisfied by trace.TraceWriter (and test doubles).
type TraceEmitter interface {
	WriteAction(event trace.ActionEvent) error
}

// MediationEngine is the transport-agnostic core that evaluates every action
// intent against the active policy. Transport bindings call Mediate for each
// intercepted request.
type MediationEngine struct {
	PolicyEngine *policy.Engine
	RunID        string
}

// NewMediationEngine creates a MediationEngine. A nil PolicyEngine puts the
// engine into permissive mode (all actions allowed).
func NewMediationEngine(eng *policy.Engine, runID string) *MediationEngine {
	return &MediationEngine{
		PolicyEngine: eng,
		RunID:        runID,
	}
}

// Mediate evaluates an ActionIntent against the policy engine and returns the
// decision. When no policy engine is configured the action is allowed by
// default.
func (me *MediationEngine) Mediate(intent ActionIntent, state policy.RunState) MediationResult {
	policyIntent := policy.ActionIntent{
		Protocol: intent.Protocol,
		Method:   intent.Method,
		Target:   intent.Target,
	}

	if raw, ok := intent.Params.([]byte); ok {
		policyIntent.Params = raw
	}

	var decision policy.AuthDecision
	if me.PolicyEngine != nil {
		decision = me.PolicyEngine.Evaluate(policyIntent, state)
	} else {
		decision = policy.AuthDecision{
			Decision: "allow",
			RuleID:   "default",
			Reason:   "no policy engine (permissive)",
		}
	}

	return MediationResult{
		Decision: decision,
		Allowed:  decision.IsAllowed(),
	}
}
