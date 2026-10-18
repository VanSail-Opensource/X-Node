//go:build !linux

package firewall

// Portable fixtures do not install kernel rules; production admission is Linux.
func bulkFreeSpace(string, int64) error { return nil }
