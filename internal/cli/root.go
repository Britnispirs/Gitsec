package cli

import (
	"fmt"
	"io"
	"os"
)

// App metadata
const (
	Version   = "0.1.0-alpha"
	BuildName = "Genesis"
)

// CLI orchestrates the execution of Gitsec subcommands.
type CLI struct {
	stdout io.Writer
	stderr io.Writer
}

// NewCLI creates a new CLI runner with standard output streams.
func NewCLI(stdout, stderr io.Writer) *CLI {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	return &CLI{stdout: stdout, stderr: stderr}
}

// Run parses arguments and routes to the matching subcommand.
func (c *CLI) Run(args []string) int {
	if len(args) == 0 {
		c.printHelp()
		return 0
	}

	command := args[0]
	cmdArgs := args[1:]

	switch command {
	case "help", "-h", "--help":
		c.printHelp()
		return 0
	case "version", "-v", "--version":
		return c.runVersion(cmdArgs)
	case "init":
		return c.runInit(cmdArgs)
	default:
		fmt.Fprintf(c.stderr, "sec: '%s' is not a gitsec command. See 'sec --help'.\n", command)
		return 1
	}
}

func (c *CLI) printHelp() {
	helpText := fmt.Sprintf(`Gitsec (sec) - The Version Control System for Software Security State (v%s)

Usage:
  sec <command> [arguments]

Core Commands:
  init        Initialize security state tracking in current repository
  version     Show the gitsec version and build information

Work in Progress Commands:
  status      Show current security posture and staged verifications
  check       Execute parallel security verifiers on the project
  commit      Record an immutable security snapshot bound to current Git commit
  diff        Show security posture differences between two revisions
  log         Show security commit history and posture timeline

Flags:
  -h, --help       Show help for command
  -v, --version    Show gitsec version

Learn more at https://github.com/Britnispirs/Gitsec
`, Version)
	fmt.Fprint(c.stdout, helpText)
}
