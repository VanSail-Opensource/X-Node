package xray

func (b *integration) setAuxiliary(tags map[string]bool) {
	copy := make(map[string]bool, len(tags))
	for tag, enabled := range tags {
		copy[tag] = enabled
	}
	b.Auxiliary.Store(&copy)
}

func (b *integration) auxiliaryAllowed(tag string) bool {
	tags := b.Auxiliary.Load()
	return tags != nil && (*tags)[tag]
}
