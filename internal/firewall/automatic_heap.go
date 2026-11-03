package firewall

type automaticExpiry []*automaticEntry

func (h automaticExpiry) Len() int           { return len(h) }
func (h automaticExpiry) Less(i, j int) bool { return h[i].deadline().Before(h[j].deadline()) }
func (h automaticExpiry) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index, h[j].index = i, j
}
func (h *automaticExpiry) Push(value any) {
	item := value.(*automaticEntry)
	item.index = len(*h)
	*h = append(*h, item)
}
func (h *automaticExpiry) Pop() any {
	items := *h
	last := len(items) - 1
	item := items[last]
	items[last], item.index = nil, -1
	*h = items[:last]
	return item
}
