package main

import "testing"

func TestBootReadinessUsesCompletedOneshotExecution(t *testing.T) {
	for _, tc := range []struct {
		name, state, result, status, start, end string
		ready                                   bool
	}{
		{"completed inactive", "inactive", "success", "0", "100", "200", true},
		{"completed retained", "active", "success", "0", "100", "200", true},
		{"never executed", "inactive", "success", "0", "0", "0", false},
		{"still running", "activating", "success", "0", "100", "0", false},
		{"failed", "failed", "exit-code", "1", "100", "200", false},
		{"no exit timestamp", "inactive", "success", "0", "100", "0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := "ActiveState=" + tc.state + "\nResult=" + tc.result + "\nExecMainStatus=" + tc.status + "\nExecMainStartTimestampMonotonic=" + tc.start + "\nExecMainExitTimestampMonotonic=" + tc.end + "\n"
			if got := completedBootRestore(output); got != tc.ready {
				t.Fatal(got, tc.ready)
			}
		})
	}
}
