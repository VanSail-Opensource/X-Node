package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/state"
)

// nft rejects every xtables compatibility expression in both its text and JSON
// parsers, and iptables-nft owns its tables through NETLINK ownership flags.
// A snapshot that contains such a table can therefore never be replayed with
// "nft -f". Those tables are captured and restored with the iptables front end
// that owns them instead.
type compatSnapshot struct {
	Family  string `json:"family"`
	Table   string `json:"table"`
	Backup  string `json:"backup"`
	Restore string `json:"restore"`
}

type compatTable struct {
	Family string
	Table  string
}

type compatTool struct {
	save    string
	restore string
}

// Prefer the explicitly nft-backed front ends, then the alternatives-managed
// commands after confirming that they report the nf_tables backend.
var compatTools = map[string][]compatTool{
	"ip": {
		{save: "iptables-nft-save", restore: "iptables-nft-restore"},
		{save: "iptables-save", restore: "iptables-restore"},
	},
	"ip6": {
		{save: "ip6tables-nft-save", restore: "ip6tables-nft-restore"},
		{save: "ip6tables-save", restore: "ip6tables-restore"},
	},
}

var compatTableName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// splitCompatTables removes tables owned by iptables-nft from the nftables
// snapshot and reports them in snapshot order.
func splitCompatTables(ruleset []byte) ([]byte, []compatTable, error) {
	lines := strings.Split(string(ruleset), "\n")
	kept := make([]string, 0, len(lines))
	tables := []compatTable{}
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "table ") {
			kept = append(kept, lines[i])
			continue
		}
		start := i
		end := i
		if !strings.HasSuffix(strings.TrimSpace(lines[i]), "}") {
			for end = i + 1; end < len(lines); end++ {
				if lines[end] == "}" {
					break
				}
			}
			if end == len(lines) {
				return nil, nil, errors.New("unterminated table in nftables snapshot")
			}
		}
		i = end
		block := lines[start : end+1]
		if !ownedByXTables(lines[start], block) {
			kept = append(kept, block...)
			continue
		}
		fields := strings.Fields(lines[start])
		if len(fields) < 3 || !compatTableName.MatchString(fields[2]) {
			return nil, nil, errors.New("unsupported table in nftables snapshot")
		}
		if _, ok := compatTools[fields[1]]; !ok {
			return nil, nil, fmt.Errorf("cannot snapshot xtables table %s %s", fields[1], fields[2])
		}
		tables = append(tables, compatTable{Family: fields[1], Table: fields[2]})
	}
	return []byte(strings.Join(kept, "\n")), tables, nil
}

// ownedByXTables reports whether a table block comes from iptables-nft. The
// owner marker covers tables whose rules were removed after iptables created
// them; the expression check covers kernels that do not report ownership.
func ownedByXTables(header string, block []string) bool {
	if strings.Contains(header, " progname ") {
		return true
	}
	for _, line := range block {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "xt" && (fields[i+1] == "match" || fields[i+1] == "target") {
				return true
			}
		}
	}
	return false
}

func (m *Manager) compatTool(ctx context.Context, family string) (compatTool, error) {
	candidates, ok := compatTools[family]
	if !ok {
		return compatTool{}, fmt.Errorf("unsupported xtables family %s", family)
	}
	for i, tool := range candidates {
		version, err := m.Runner.Run(ctx, tool.save, "--version")
		if err != nil {
			continue
		}
		if i > 0 && !strings.Contains(string(version), "nf_tables") {
			continue
		}
		return tool, nil
	}
	return compatTool{}, fmt.Errorf("no nftables-backed iptables utilities for %s", family)
}

// saveCompat stores one ruleset per iptables-owned table so recovery can replay
// exactly what nft cannot express.
func (m *Manager) saveCompat(ctx context.Context, tables []compatTable, prefix string) ([]compatSnapshot, error) {
	saved := make([]compatSnapshot, 0, len(tables))
	for _, t := range tables {
		tool, err := m.compatTool(ctx, t.Family)
		if err != nil {
			return nil, err
		}
		rules, err := m.Runner.Run(ctx, tool.save, "-t", t.Table)
		if err != nil {
			return nil, fmt.Errorf("cannot snapshot %s %s rules", t.Family, t.Table)
		}
		path := filepath.Join(m.Dir, fmt.Sprintf("%s-%s-%s.rules", prefix, t.Family, t.Table))
		if err = state.AtomicWrite(path, rules, 0600); err != nil {
			return nil, err
		}
		saved = append(saved, compatSnapshot{Family: t.Family, Table: t.Table, Backup: path, Restore: tool.restore})
	}
	return saved, nil
}

// restoreCompat replays the captured compatibility tables. The nft snapshot
// begins with "flush ruleset", so the iptables front end must run afterwards.
func (m *Manager) restoreCompat(ctx context.Context, snapshots []compatSnapshot) error {
	for _, s := range snapshots {
		if !compatTableName.MatchString(s.Table) || filepath.Clean(filepath.Dir(s.Backup)) != filepath.Clean(m.Dir) {
			return errors.New("invalid saved xtables snapshot")
		}
		valid := false
		for _, tool := range compatTools[s.Family] {
			if tool.restore == s.Restore {
				valid = true
				break
			}
		}
		if !valid {
			return errors.New("invalid saved xtables restore command")
		}
		if _, err := m.Runner.Run(ctx, s.Restore, s.Backup); err != nil {
			return err
		}
	}
	return nil
}

func originalCompatPath(dir string) string { return filepath.Join(dir, "original-compat.json") }

func writeOriginalCompat(dir string, snapshots []compatSnapshot) error {
	b, err := json.Marshal(snapshots)
	if err != nil {
		return err
	}
	return state.AtomicWrite(originalCompatPath(dir), b, 0600)
}

// restoreOriginalCompat replays the compatibility tables of the uninstall
// snapshot; hosts that never had them keep an inert record.
func (m *Manager) restoreOriginalCompat(ctx context.Context) error {
	b, err := os.ReadFile(originalCompatPath(m.Dir))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var snapshots []compatSnapshot
	if err = json.Unmarshal(b, &snapshots); err != nil {
		return errors.New("invalid original xtables snapshot")
	}
	return m.restoreCompat(ctx, snapshots)
}
