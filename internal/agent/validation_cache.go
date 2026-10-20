package agent

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// validationIdentity rechecks material, not timestamps. Validation with
// synthetic ACME certificates is cached separately and never activated.
func (a *Agent) validationIdentity(c protocol.Config, policy geodata.Policy) ([32]byte, error) {
	h := sha256.New()
	_, _ = h.Write(protocol.NativeIdentity(c))
	_, _ = h.Write([]byte(assetKey(c, policy)))
	geo, _ := json.Marshal(c.Firewall.SourceGeoIP)
	_, _ = h.Write(geo)
	var native any
	if err := json.Unmarshal(c.Xray, &native); err != nil {
		return [32]byte{}, err
	}
	paths := []string{}
	var walk func(any)
	walk = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			for k, item := range v {
				if k == "certificateFile" || k == "keyFile" {
					if path, ok := item.(string); ok && path != "" {
						paths = append(paths, path)
					}
				}
				walk(item)
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		}
	}
	walk(native)
	for _, spec := range c.Certificates {
		cfg := spec.Config
		if cfg.CertMode == "file" || (cfg.CertMode == "" && cfg.CertFile != "") {
			paths = append(paths, cfg.CertFile, cfg.KeyFile)
		}
	}
	target := geodata.Resolve(filepath.Join(a.Dir, "geodata"))
	if a.geoCandidate != "" && a.geoCandidateKey == assetKey(c, policy) {
		target = a.geoCandidate
	}
	if strings.Contains(string(c.Xray), "geosite:") || len(policy.Assets) > 0 || hasGeosite(c.BlockedDomains) {
		paths = append(paths, filepath.Join(target, "geosite.dat"))
	}
	slices.Sort(paths)
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return [32]byte{}, errors.New("cannot read native validation material")
		}
		_, _ = h.Write([]byte(path))
		n, err := io.Copy(h, io.LimitReader(file, geodata.MaxAssetBytes+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil || n > geodata.MaxAssetBytes {
			return [32]byte{}, errors.New("invalid native validation material")
		}
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key, nil
}

func hasGeosite(domains []string) bool {
	for _, domain := range domains {
		if strings.HasPrefix(domain, "geosite:") {
			return true
		}
	}
	return false
}
