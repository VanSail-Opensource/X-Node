package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Canonical object ordering binds command replays without rounding exact JSON
// numbers. Walk tokens before map construction so duplicate members cannot hide
// an earlier invalid value or change typed nested-object merge semantics.
func canonicalCommandArgs(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > protocol.MaxFrameBytes {
		return nil, errors.New("utility arguments exceed bounds")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var preserveOrder bool
	value, err := commandArgValue(decoder, 0, &preserveOrder)
	if err != nil {
		return nil, err
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, errors.New("utility arguments must be an object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("utility arguments contain trailing JSON")
	}
	if preserveOrder {
		// Typed Go fields accept case-folded aliases, while extension maps have
		// case-sensitive keys. Sorting aliases could change last/merge wins.
		// Preserve their original order and bind replay conservatively instead.
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			return nil, errors.New("invalid utility arguments")
		}
		return compact.Bytes(), nil
	}
	return json.Marshal(value)
}

func commandArgValue(decoder *json.Decoder, depth int, preserveOrder *bool) (any, error) {
	if depth > 128 {
		return nil, errors.New("utility arguments exceed nesting bound")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, errors.New("invalid utility arguments")
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := map[string]any{}
		folded := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok {
				return nil, errors.New("invalid utility argument key")
			}
			if _, duplicate := object[key]; duplicate {
				return nil, errors.New("duplicate utility argument key")
			}
			fold := foldedCommandKey(key)
			if folded[fold] {
				*preserveOrder = true
			}
			folded[fold] = true
			value, err := commandArgValue(decoder, depth+1, preserveOrder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return nil, errors.New("invalid utility argument object")
		}
		return object, nil
	case '[':
		array := []any{}
		for decoder.More() {
			value, err := commandArgValue(decoder, depth+1, preserveOrder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return nil, errors.New("invalid utility argument array")
		}
		return array, nil
	default:
		return nil, errors.New("invalid utility argument delimiter")
	}
}

// Equivalent to Unicode simple-fold comparison without quadratic sibling scans.
func foldedCommandKey(key string) string {
	var out strings.Builder
	out.Grow(len(key))
	for _, r := range key {
		least := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < least {
				least = next
			}
		}
		out.WriteRune(least)
	}
	return out.String()
}
