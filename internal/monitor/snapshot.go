package monitor

import (
	"maps"
	"slices"
)

// clone keeps the latest sample immutable without serializing it in order to
// copy it. The third-party scalar structs are copied by value.
func (s Snapshot) clone() Snapshot {
	if s.Host != nil {
		host := *s.Host
		s.Host = &host
	}
	if s.Load != nil {
		load := *s.Load
		s.Load = &load
	}
	if s.Memory != nil {
		memory := *s.Memory
		s.Memory = &memory
	}
	if s.Swap != nil {
		swap := *s.Swap
		s.Swap = &swap
	}
	s.CPU = slices.Clone(s.CPU)
	for i := range s.CPU {
		s.CPU[i].Flags = slices.Clone(s.CPU[i].Flags)
	}
	s.CPUUsage = slices.Clone(s.CPUUsage)
	s.Disks = slices.Clone(s.Disks)
	s.DiskIO = maps.Clone(s.DiskIO)
	s.Interfaces = slices.Clone(s.Interfaces)
	for i := range s.Interfaces {
		s.Interfaces[i].Addresses = slices.Clone(s.Interfaces[i].Addresses)
	}
	s.GPU = slices.Clone(s.GPU)
	s.Errors = maps.Clone(s.Errors)
	return s
}
