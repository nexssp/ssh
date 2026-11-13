package ssh

import "errors"

// ErrNoMatchingHostKey indicates that a trust request contained no valid key for
// the exact requested host and port.
var ErrNoMatchingHostKey = errors.New("ssh trust: no matching valid host key; fetch the fingerprint again")

// ErrTrustInputLimit indicates the supplied host-key data exceeds safe bounds.
var ErrTrustInputLimit = errors.New("ssh trust: key data exceeds allowed limits")
