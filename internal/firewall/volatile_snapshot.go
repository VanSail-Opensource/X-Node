package firewall

import (
	"errors"
	"strings"
)

// withoutVolatileProtection retains nft's canonical snapshot structure while
// excluding observed node/member protection from rollback files. Authorization
// desired state is durable separately; derived source sets are re-projected.
func withoutVolatileProtection(raw []byte) ([]byte, error) {
	lines := strings.Split(string(raw), "\n")
	kept := make([]string, 0, len(lines))
	managed, trusted := false, false
	depth := 0
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if !managed {
			managed = trim == "table inet x_node {"
			kept = append(kept, line)
			continue
		}
		if depth > 0 {
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth < 0 {
				return nil, errors.New("invalid volatile source snapshot")
			}
			continue
		}
		if !trusted {
			fields := strings.Fields(trim)
			trusted = len(fields) == 3 && fields[0] == "set" && (fields[1] == "trusted_v4" || fields[1] == "trusted_v6") && fields[2] == "{"
			if line == "}" {
				managed = false
			}
			kept = append(kept, line)
			continue
		}
		if strings.HasPrefix(trim, "elements =") {
			depth = strings.Count(line, "{") - strings.Count(line, "}")
			if !strings.Contains(line, "{") || depth < 0 {
				return nil, errors.New("invalid volatile source elements")
			}
			continue
		}
		if trim == "}" {
			trusted = false
		}
		kept = append(kept, line)
	}
	if depth != 0 || trusted || managed {
		return nil, errors.New("unterminated volatile source snapshot")
	}
	return []byte(strings.Join(kept, "\n")), nil
}
