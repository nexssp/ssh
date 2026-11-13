package ssh

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunCommandRejectsEmptyCommandWithoutNetwork(t *testing.T) {
	_, err := RunCommand(context.Background(), Profile{}, "  ", time.Second)
	if err == nil || !strings.Contains(err.Error(), "command is required") {
		t.Fatalf("RunCommand() error = %v", err)
	}
}

func TestRunCommandRejectsTimeoutAboveMaximumWithoutNetwork(t *testing.T) {
	_, err := RunCommand(context.Background(), Profile{}, "true", MaxOperationTimeout+time.Second)
	if err == nil || !strings.Contains(err.Error(), "no greater than") {
		t.Fatalf("RunCommand() error = %v", err)
	}
}
