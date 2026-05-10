package sandbox

import "testing"

func TestPathHasParent(t *testing.T) {
	cases := []struct {
		name   string
		child  string
		parent string
		want   bool
	}{
		// The bug fix's reason for being: a strict prefix check would
		// accept /foo/barbaz as a child of /foo/bar, which would let an
		// attacker escape a sandbox mount by naming a sibling directory.
		{"prefix-sibling-not-parent", "/foo/barbaz", "/foo/bar", false},
		{"genuine-child", "/foo/bar/baz", "/foo/bar", true},
		{"exact-match-is-parent", "/foo/bar", "/foo/bar", true},
		{"strict-non-parent", "/foo/other", "/foo/bar", false},

		// Root edge cases — "/" matches every absolute path, but not
		// empty strings or unanchored paths.
		{"root-matches-any-abs", "/anything", "/", true},
		{"root-matches-self", "/", "/", true},
		{"root-rejects-empty", "", "/", false},

		// Empty parent never matches — guards against zero-value mounts.
		{"empty-parent", "/anywhere", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pathHasParent(tc.child, tc.parent)
			if got != tc.want {
				t.Errorf("pathHasParent(%q, %q) = %v, want %v",
					tc.child, tc.parent, got, tc.want)
			}
		})
	}
}
