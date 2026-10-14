package dnsproviders

import (
	"github.com/caddyserver/certmagic"
)

func init() {
	Register(&Provider{
		Names:   []string{"vultr"},
		EnvVars: []string{"VULTR_API_TOKEN"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			token := firstOf(env, "VULTR_API_TOKEN", "VULTR_API_KEY")
			if token == "" {
				return nil, missingEnvErr("vultr", "VULTR_API_TOKEN")
			}
			return &vultrProvider{token: token}, nil
		},
	})
}
