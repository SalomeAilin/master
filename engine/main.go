package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
)

const version = "0.3.7-wired-app"

func command(arguments []string) error {
	if len(arguments) == 0 || len(arguments) == 1 && (arguments[0] == "--help" || arguments[0] == "-h") {
		fmt.Println("network-domain-engine: status | evidence | wired-app | config | prepare-service | check-service | upgrade | maintenance | version")
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
	listenFD := flags.Int("listen-fd", -1, "optional inherited TCP4 loopback listener; run only")
	limit := flags.Int64("log-max-size", 2097152, "maximum bytes in a newly written log")
	backups := flags.Int("log-max-backups", 3, "numbered log archives")
	flags.Bool("disable-color", true, "compatibility flag; output is always uncolored")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" {
		return errors.New("configuration path required; positional arguments rejected")
	}
	if *listenFD != -1 && (arguments[0] != "run" || *listenFD < 3 || *listenFD > 1024) {
		return errors.New("invalid inherited listener descriptor")
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
	if *listenFD >= 3 {
		var listener net.Listener
		listener, err = inheritedListener(*listenFD, c.Listen)
		if err == nil {
			defer listener.Close()
			err = startEngineListener(ctx, c, logger, listener)
		}
	} else {
		err = startEngine(ctx, c, logger)
	}
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

func inheritedListener(fd int, address string) (net.Listener, error) {
	f := os.NewFile(uintptr(fd), "inherited proxy listener")
	if f == nil {
		return nil, errors.New("invalid inherited listener")
	}
	defer f.Close()
	listener, err := net.FileListener(f)
	if err != nil {
		return nil, err
	}
	tcp, ok := listener.Addr().(*net.TCPAddr)
	if !ok || tcp.IP.To4() == nil || !tcp.IP.IsLoopback() || listener.Addr().String() != address {
		listener.Close()
		return nil, errors.New("inherited listener differs from configured IPv4 loopback endpoint")
	}
	return listener, nil
}
