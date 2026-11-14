package update

import (
	json "encoding/json/v2"
	"errors"
	"os"
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/state"
)

const maxTransactionBytes = 64 << 10

func readTransaction(path string) (Transaction, error) {
	var tx Transaction
	raw, err := state.ReadRecoveryFile(path, maxTransactionBytes)
	if err != nil {
		return tx, err
	}
	if json.Unmarshal(raw, &tx, json.RejectUnknownMembers(true)) != nil || tx.ID == "" || len(tx.ID) > 128 || !stableVersion.MatchString(tx.Version) || tx.Deadline.IsZero() || !validBinaryPath(tx.NodePath) || !validBinaryPath(tx.CLIPath) || tx.NodePath == tx.CLIPath || tx.Unit != "" && tx.Unit != "x-node-upgrade-rollback" {
		return Transaction{}, errors.New("invalid upgrade transaction; preserve recovery evidence")
	}
	switch tx.Status {
	case "pending", "confirmed", "rolled_back", "failed":
		return tx, nil
	default:
		return Transaction{}, errors.New("invalid upgrade transaction status")
	}
}

func validBinaryPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Dir(path) != path
}

// PendingTransaction gives all recovery/migration observers the same read-only
// state interpretation. Missing state is idle; invalid evidence is an error,
// never permission to adopt a format the rollback binary may not understand.
func PendingTransaction(dir string) (bool, error) {
	tx, err := readTransaction(filepath.Join(dir, "transaction.json"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return tx.Status == "pending", nil
}
