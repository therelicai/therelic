package delegation

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/therelicai/therelic/internal/policy"
)

// DelegationNode represents a single agent session in a delegation chain.
type DelegationNode struct {
	RunID      string
	AgentName  string
	PolicyHash string
	Depth      int
	RootRunID  string
}

// DelegationEdge connects a parent session to a child session.
type DelegationEdge struct {
	ParentRunID string
	ChildRunID  string
}

// Graph is a DAG tracking delegation relationships between agent sessions.
// Effective policy at any node = intersection of all ancestor policies.
type Graph struct {
	Nodes map[string]*DelegationNode
	Edges []DelegationEdge
	Root  string
}

// NewGraph creates an empty delegation graph rooted at rootRunID.
func NewGraph(rootRunID string) *Graph {
	return &Graph{
		Nodes: make(map[string]*DelegationNode),
		Root:  rootRunID,
	}
}

func (g *Graph) AddNode(node *DelegationNode) {
	g.Nodes[node.RunID] = node
}

func (g *Graph) AddEdge(parentRunID, childRunID string) {
	g.Edges = append(g.Edges, DelegationEdge{
		ParentRunID: parentRunID,
		ChildRunID:  childRunID,
	})
}

// AncestorChain returns the run IDs from root to the immediate parent of runID,
// in top-down order.
func (g *Graph) AncestorChain(runID string) []string {
	parentOf := make(map[string]string)
	for _, e := range g.Edges {
		parentOf[e.ChildRunID] = e.ParentRunID
	}
	var chain []string
	current := runID
	for {
		parent, ok := parentOf[current]
		if !ok {
			break
		}
		chain = append([]string{parent}, chain...)
		current = parent
	}
	return chain
}

// EvaluateWithDelegation walks root→node and intersects all policies.
// The action is allowed only if ALL ancestor policies (and the current one) allow it.
func EvaluateWithDelegation(
	intent policy.ActionIntent,
	currentPolicy *policy.Policy,
	ancestorPolicies []*policy.Policy,
	state policy.RunState,
) policy.AuthDecision {
	for _, ap := range ancestorPolicies {
		result := policy.Evaluate(intent, ap, state)
		if result.IsDenied() {
			result.Reason = fmt.Sprintf("denied by ancestor policy: %s", result.Reason)
			return result
		}
	}
	return policy.Evaluate(intent, currentPolicy, state)
}

// Environment variable names used for delegation chain propagation.
const (
	EnvRunID           = "RELIC_RUN_ID"
	EnvParentRunID     = "RELIC_PARENT_RUN_ID"
	EnvParentPolicy    = "RELIC_PARENT_POLICY"
	EnvDelegationDepth = "RELIC_DELEGATION_DEPTH"
	EnvDelegationRoot  = "RELIC_DELEGATION_ROOT"
)

// DetectParentSession reads delegation env vars to determine if this process
// was spawned as a child in a delegation chain. Returns zero values and
// isChild=false for root sessions.
func DetectParentSession() (parentRunID, parentPolicy, delegationRoot string, depth int, isChild bool) {
	parentRunID = os.Getenv(EnvParentRunID)
	if parentRunID == "" {
		parentRunID = os.Getenv(EnvRunID)
	}
	if parentRunID == "" {
		return "", "", "", 0, false
	}
	parentPolicy = os.Getenv(EnvParentPolicy)
	delegationRoot = os.Getenv(EnvDelegationRoot)
	depthStr := os.Getenv(EnvDelegationDepth)
	if depthStr != "" {
		fmt.Sscanf(depthStr, "%d", &depth)
	}
	if delegationRoot == "" {
		delegationRoot = parentRunID
	}
	return parentRunID, parentPolicy, delegationRoot, depth, true
}

// CachePolicy writes policy data to policiesDir/<hash>.yaml and returns the path.
func CachePolicy(policiesDir string, policyData []byte, hash string) (string, error) {
	if err := os.MkdirAll(policiesDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(policiesDir, hash+".yaml")
	return path, os.WriteFile(path, policyData, 0o644)
}

// LoadCachedPolicy loads a policy from a previously cached file.
func LoadCachedPolicy(path string) (*policy.Policy, error) {
	return policy.Load(path)
}

// SetChildEnv builds an environment slice for a child process that includes
// delegation chain variables. The returned slice starts with os.Environ().
func SetChildEnv(cmd interface{ Environ() []string }, runID, policyPath, rootRunID string, depth int) []string {
	env := os.Environ()
	env = append(env,
		fmt.Sprintf("%s=%s", EnvRunID, runID),
		fmt.Sprintf("%s=%s", EnvParentRunID, runID),
		fmt.Sprintf("%s=%s", EnvParentPolicy, policyPath),
		fmt.Sprintf("%s=%d", EnvDelegationDepth, depth+1),
		fmt.Sprintf("%s=%s", EnvDelegationRoot, rootRunID),
	)
	return env
}
