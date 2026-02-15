package main

import (
	"fmt"
	"github.com/vishnu303/chaathan-flow/cli"
	"os"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
