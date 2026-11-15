package cli

import (
	"fmt"
	"runtime"
)

func (c *CLI) runVersion(args []string) int {
	fmt.Fprintf(c.stdout, "sec version %s (%s) %s/%s\n",
		Version,
		BuildName,
		runtime.GOOS,
		runtime.GOARCH,
	)
	return 0
}
