package state

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

// Connection-derived admission controls live in the accepted in-memory view.
// Copy only the authorization slices when serializing; traffic journals and
// credentials retain their exact durable representation without another clone.
func withoutConnectionControls(data Data) (Data, bool) {
	changed := false
	cleanUsers := func(users []protocol.User) []protocol.User {
		for _, user := range users {
			if user.BlockNew {
				copy := append([]protocol.User(nil), users...)
				for i := range copy {
					copy[i].BlockNew = false
				}
				changed = true
				return copy
			}
		}
		return users
	}
	data.Users = cleanUsers(data.Users)
	if data.Config != nil {
		copy := *data.Config
		copy.Users = cleanUsers(copy.Users)
		data.Config = &copy
	}
	return data, changed
}
