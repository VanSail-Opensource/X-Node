package xray

import "os"

type nativeEnvironmentValue struct {
	value   string
	present bool
}

// The process hosts one serving Xray runtime. Remember the original process
// value of every active override so an omitted key can relinquish ownership.
// Access is serialized by nativeEnvironmentMu, including candidate preparation.
var nativeRuntimeBaseline map[string]nativeEnvironmentValue

// beginNativeRuntimeEnvironment stages a complete environment, not a patch.
// Call one of restore and commit while still holding nativeEnvironmentMu.
// restore can also be called immediately before starting a recovery core.
func beginNativeRuntimeEnvironment(values map[string]string) (restore, commit func(), err error) {
	before := make(map[string]nativeEnvironmentValue)
	var next map[string]nativeEnvironmentValue
	if len(values) > 0 {
		next = make(map[string]nativeEnvironmentValue, len(values))
	}
	pending := true
	restore = func() {
		if !pending {
			return
		}
		pending = false
		for key, original := range before {
			_ = writeNativeEnvironment(key, original)
		}
	}
	commit = func() {
		if pending {
			pending = false
			nativeRuntimeBaseline = next
		}
	}
	change := func(key string, previous, candidate nativeEnvironmentValue) error {
		if previous == candidate {
			return nil
		}
		if err := writeNativeEnvironment(key, candidate); err != nil {
			return err
		}
		before[key] = previous
		return nil
	}
	for key, original := range nativeRuntimeBaseline {
		if _, keep := values[key]; !keep {
			if err := change(key, readNativeEnvironment(key), original); err != nil {
				restore()
				return nil, nil, err
			}
		}
	}
	for key, value := range values {
		previous := readNativeEnvironment(key)
		original, managed := nativeRuntimeBaseline[key]
		if !managed {
			original = previous
		}
		next[key] = original
		if err := change(key, previous, nativeEnvironmentValue{value, true}); err != nil {
			restore()
			return nil, nil, err
		}
	}
	return restore, commit, nil
}

func readNativeEnvironment(key string) nativeEnvironmentValue {
	value, present := os.LookupEnv(key)
	return nativeEnvironmentValue{value, present}
}

func writeNativeEnvironment(key string, value nativeEnvironmentValue) error {
	if !value.present {
		return os.Unsetenv(key)
	}
	return os.Setenv(key, value.value)
}

// Native inputs can interpolate allowed process options into addresses and
// ports. Their JSON section keys cannot capture those implicit dependencies.
// Agent-managed asset generation changes retain the existing narrower
// routing/static invalidation rather than rebuilding all native inputs.
func nativeBuilderEnvironmentChanged(previous *Prepared, next map[string]string) bool {
	const assetLocation = "XRAY_LOCATION_ASSET"
	prior, _ := previous.Native["env"].(map[string]any)
	for key, value := range prior {
		if key != assetLocation {
			if candidate, ok := next[key]; !ok || candidate != value {
				return true
			}
		}
	}
	for key := range next {
		if _, ok := prior[key]; key != assetLocation && !ok {
			return true
		}
	}
	return false
}
