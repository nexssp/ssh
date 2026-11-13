// Package ssh provides strict, profile-based SSH command execution for local NFlow runtimes.
// Hostnames, usernames, identities, and known_hosts trust are loaded from local profiles;
// commands are bounded and every host key is checked against OpenSSH known_hosts data.
package ssh
