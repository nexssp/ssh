package sftp

// ValidateMaxBytes validates a configured transfer cap. Zero selects DefaultMaxBytes.
func ValidateMaxBytes(maxBytes int64) error {
	_, err := transferLimit(maxBytes)
	return err
}
