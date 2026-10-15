package firewall

import "errors"

// errUnchanged identifies failures known to precede any kernel commit.
var errUnchanged = errors.New("kernel firewall unchanged")
