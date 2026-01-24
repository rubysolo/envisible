package main

import (
	"os"

	"github.com/rubysolo/envisible/cmd"
	"github.com/rubysolo/envisible/pkg/ui"
)

func main() {
	if err := cmd.Execute(); err != nil {
		ui.Error("%v", err)
		os.Exit(1)
	}
}
