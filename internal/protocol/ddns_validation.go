package protocol

import (
	"errors"
	"net/netip"
	"strings"
	"unicode"

	"github.com/VanSail-Opensource/X-Node/internal/httpguard"
	"golang.org/x/net/idna"
)

// RFC 2181 section 8 defines the effective TTL range as 0 through 2^31-1.
// Bounding seconds before conversion also prevents time.Duration overflow.
const MaxDDNSTTLSeconds = 1<<31 - 1

// Validate checks DDNS execution inputs independently of provider ownership.
// Config.Validate also checks provider references and built-in discovery policy.
func (job DDNSJob) Validate() error {
	if !ValidName(job.ID) || job.Generation != "" && !ValidName(job.Generation) || job.IntervalSeconds < 0 || job.IntervalSeconds > 86400 || job.TTLSeconds < 0 || job.TTLSeconds > MaxDDNSTTLSeconds {
		return errors.New("invalid DDNS identity or interval")
	}
	if job.IPv4 == "" && job.IPv6 == "" {
		return errors.New("DDNS job requires an address source")
	}
	if strings.ContainsAny(job.Interface, "/\\") || strings.IndexFunc(job.Interface, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return errors.New("invalid DDNS interface")
	}
	for index, source := range []string{job.IPv4, job.IPv6} {
		lookup := []string{job.IPv4URL, job.IPv6URL}[index]
		if lookup != "" {
			if _, err := httpguard.HTTPSURL(lookup); err != nil {
				return errors.New("invalid DDNS HTTPS lookup")
			}
		}
		if source == "" {
			continue
		}
		if source == "auto" {
			if job.Interface == "" && lookup == "" {
				return errors.New("DDNS auto address requires an interface or HTTPS lookup")
			}
			continue
		}
		address, err := netip.ParseAddr(source)
		if err != nil || address.Zone() != "" || !address.IsGlobalUnicast() || address.Unmap().Is4() != (index == 0) {
			return errors.New("invalid DDNS address family or value")
		}
	}
	if job.Provider != BuiltinDDNSProvider {
		_, _, err := DDNSRecordNames(job.Zone, job.Name)
		return err
	}
	return nil
}

// DDNSRecordNames canonicalizes the exact owned zone/name before provider I/O.
// Apex, absolute names, IDNA, service labels and leading wildcards are supported;
// a suffix without a label boundary cannot escape the selected zone.
func DDNSRecordNames(zone, name string) (string, string, error) {
	zone, err := ddnsDomain(zone, false)
	if err != nil {
		return "", "", err
	}
	if name == "@" {
		name = zone
	} else if name, err = ddnsDomain(name, true); err != nil {
		return "", "", err
	}
	if name != zone && !strings.HasSuffix(name, "."+zone) {
		return "", "", errors.New("DDNS name is outside its zone")
	}
	return zone + ".", name, nil
}

func ddnsDomain(name string, wildcard bool) (string, error) {
	if name == "" || strings.IndexFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return "", errors.New("invalid DDNS record name")
	}
	name = strings.Map(func(r rune) rune {
		if r == '\u3002' || r == '\uff0e' || r == '\uff61' {
			return '.'
		}
		return unicode.ToLower(r)
	}, name)
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	for index, label := range labels {
		if label == "*" && wildcard && index == 0 && len(labels) > 1 {
			continue
		}
		// DNS owner labels may contain underscores; IDNA applies to the other
		// labels and never interprets backslash escapes or URL punctuation.
		if strings.IndexFunc(label, func(r rune) bool { return r > unicode.MaxASCII }) >= 0 {
			ascii, err := idna.Lookup.ToASCII(label)
			if err != nil {
				return "", errors.New("invalid DDNS record label")
			}
			label = strings.ToLower(ascii)
		}
		if len(label) == 0 || len(label) > 63 {
			return "", errors.New("invalid DDNS record label length")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return "", errors.New("invalid DDNS record label")
			}
		}
		labels[index] = label
	}
	name = strings.Join(labels, ".")
	if len(name) > 253 {
		return "", errors.New("DDNS record name is too long")
	}
	return name, nil
}
