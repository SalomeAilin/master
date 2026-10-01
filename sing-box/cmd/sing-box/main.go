//go:build !generate

package main

import "github.com/sagernet/sing-box/log"

func main() {
	defer func() {
		if serviceLogWriter != nil {
			serviceLogWriter.Close()
		}
	}()
	if err := mainCommand.Execute(); err != nil {
		log.Fatal(err)
	}
}
