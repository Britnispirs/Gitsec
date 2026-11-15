package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLI_Version(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := NewCLI(&stdout, &stderr)

	exitCode := app.Run([]string{"version"})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	if !strings.Contains(output, "sec version 0.1.0-alpha") {
		t.Errorf("expected version output to contain 'sec version 0.1.0-alpha', got: %s", output)
	}
}

func TestCLI_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := NewCLI(&stdout, &stderr)

	exitCode := app.Run([]string{"--help"})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	if !strings.Contains(output, "Gitsec (sec)") {
		t.Errorf("expected help output to mention 'Gitsec (sec)', got: %s", output)
	}
}

func TestCLI_UnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := NewCLI(&stdout, &stderr)

	exitCode := app.Run([]string{"unknown-xyz"})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 for unknown command, got %d", exitCode)
	}

	errOutput := stderr.String()
	if !strings.Contains(errOutput, "is not a gitsec command") {
		t.Errorf("expected error message for unknown command, got: %s", errOutput)
	}
}
