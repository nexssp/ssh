package ssh

import "time"

// ValidateTimeout applies the command and transfer timeout defaults and hard maximum.
func ValidateTimeout(timeout time.Duration) (time.Duration, error) {
	return boundedTimeout(timeout)
}
