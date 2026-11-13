// Package sftp provides bounded SSH-based file upload and download operations.
//
// Typical use:
//
//	result, err := sftp.Download(ctx, profile, "/srv/report.csv", "./report.csv", 0, 2*time.Minute)
//
// Transfers use SSH profiles and strict known_hosts checking from the sibling ssh package.
package sftp
