package main

import (
	"os"

	"github.com/Britnispirs/Gitsec/internal/cli"
)

func main() {
	app := cli.NewCLI(os.Stdout, os.Stderr)
	exitCode := app.Run(os.Args[1:])
	os.Exit(exitCode)
}
