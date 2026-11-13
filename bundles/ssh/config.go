package ssh

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxOpenSSHConfigBytes  = 1 << 20
	maxOpenSSHIncludeDepth = 12
	maxOpenSSHConfigFiles  = 256
)

// ConfigAlias is a non-secret SSH host alias read from a local OpenSSH config.
type ConfigAlias struct {
	Alias string `json:"alias"`
}

// ListOpenSSHConfigAliases lists concrete Host aliases from the current user's
// ~/.ssh/config, following bounded Include directives. Wildcard and negated Host
// patterns are not returned. This lists names only; it does not evaluate every
// OpenSSH directive or make an alias an authenticated SSH profile.
func ListOpenSSHConfigAliases() ([]ConfigAlias, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("ssh config: locate user home: %w", err)
	}
	return ReadOpenSSHConfigAliases(filepath.Join(home, ".ssh", "config"))
}

// ReadOpenSSHConfigAliases lists aliases from a specific OpenSSH config file.
// A missing config file is treated as an empty config, matching OpenSSH's
// optional per-user configuration behavior.
func ReadOpenSSHConfigAliases(filename string) ([]ConfigAlias, error) {
	if strings.TrimSpace(filename) == "" {
		return nil, errors.New("ssh config: file path is required")
	}
	aliases := make(map[string]string)
	if err := readOpenSSHConfigAliases(filename, make(map[string]bool), aliases, 0); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(aliases))
	for key := range aliases {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return strings.ToLower(aliases[keys[i]]) < strings.ToLower(aliases[keys[j]])
	})
	result := make([]ConfigAlias, 0, len(keys))
	for _, key := range keys {
		result = append(result, ConfigAlias{Alias: aliases[key]})
	}
	return result, nil
}

func readOpenSSHConfigAliases(filename string, visited map[string]bool, aliases map[string]string, depth int) error {
	if depth > maxOpenSSHIncludeDepth {
		return nil
	}
	filename = filepath.Clean(filename)
	visitKey := strings.ToLower(filename)
	if visited[visitKey] {
		return nil
	}
	if len(visited) >= maxOpenSSHConfigFiles {
		return fmt.Errorf("ssh config: include tree exceeds %d files", maxOpenSSHConfigFiles)
	}
	visited[visitKey] = true

	file, err := os.Open(filename)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ssh config: open %q: %w", filename, err)
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("ssh config: stat %q: %w", filename, err)
	}
	if info.Size() > maxOpenSSHConfigBytes {
		return fmt.Errorf("ssh config: %q exceeds %d bytes", filename, maxOpenSSHConfigBytes)
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxOpenSSHConfigBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "host":
			for _, pattern := range fields[1:] {
				alias := strings.Trim(pattern, "\"'")
				if !isConcreteOpenSSHAlias(alias) {
					continue
				}
				aliases[strings.ToLower(alias)] = alias
			}
		case "include":
			for _, rawPattern := range fields[1:] {
				pattern := expandOpenSSHInclude(rawPattern)
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(filepath.Dir(filename), pattern)
				}
				matches, globErr := filepath.Glob(filepath.Clean(pattern))
				if globErr != nil {
					continue
				}
				for _, includePath := range matches {
					if err := readOpenSSHConfigAliases(includePath, visited, aliases, depth+1); err != nil {
						return err
					}
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("ssh config: read %q: %w", filename, err)
	}
	return nil
}

func isConcreteOpenSSHAlias(alias string) bool {
	if alias == "" || strings.HasPrefix(alias, "-") || strings.ContainsAny(alias, "!*?") {
		return false
	}
	for _, r := range alias {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-", r) {
			continue
		}
		return false
	}
	return true
}

func expandOpenSSHInclude(value string) string {
	value = strings.Trim(value, "\"'")
	value = os.ExpandEnv(value)
	if value == "~" || strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			value = filepath.Join(home, strings.TrimLeft(value[1:], `/\`))
		}
	}
	return filepath.FromSlash(value)
}
