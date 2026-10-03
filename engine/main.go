package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

const version = "0.2.0-unified"

func command(arguments []string) error {
	if len(arguments) == 0 || len(arguments) == 1 && (arguments[0] == "--help" || arguments[0] == "-h") {
		fmt.Println("network-domain-engine: status | evidence | config | prepare-service | check-service | upgrade | maintenance | version")
		fmt.Println("The installed service manages its workers; do not start worker copies manually.")
		return nil
	}
	if handled, err := applicationCommand(arguments); handled {
		return err
	}
	if arguments[0] == "version" {
		fmt.Println("network-domain-engine", version)
		return nil
	}
	if arguments[0] != "run" && arguments[0] != "check" {
		return errors.New("unknown command")
	}
	flags := flag.NewFlagSet(arguments[0], flag.ContinueOnError)
	path := flags.String("c", "", "independent configuration path")
	logPath := flags.String("log-file", "", "private rotating log path")
	limit := flags.Int64("log-max-size", 2097152, "maximum bytes in a newly written log")
	backups := flags.Int("log-max-backups", 3, "numbered log archives")
	flags.Bool("disable-color", true, "compatibility flag; output is always uncolored")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" {
		return errors.New("configuration path required; positional arguments rejected")
	}
	var writer io.Writer = os.Stdout
	if *logPath != "" {
		log, err := openPrivateLog(*logPath, *limit, *backups)
		if err != nil {
			return err
		}
		defer log.Close()
		writer = log
	}
	logger := &eventLog{writer: writer}
	c, err := loadConfig(*path)
	if err == nil {
		if arguments[0] == "check" {
			_, err = newRules(c)
		}
	}
	if err != nil {
		logger.write("startup_failed", 0, map[string]any{"error": err.Error()})
		return err
	}
	if arguments[0] == "check" {
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	err = startEngine(ctx, c, logger)
	if err != nil {
		logger.write("startup_failed", 0, map[string]any{"error": err.Error()})
	}
	return err
}

func main() {
	if err := command(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
