package main

import (
	"context"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/spf13/cobra"
)

var (
	globalCtx         context.Context
	configPaths       []string
	configDirectories []string
	workingDir        string
	disableColor      bool
	logFile           string
	logMaxSize        int64
	logMaxBackups     int
	serviceLogWriter  *log.RotatingWriter
)

var mainCommand = &cobra.Command{
	Use:              "network-domain-engine",
	PersistentPreRun: preRun,
}

func init() {
	mainCommand.PersistentFlags().StringArrayVarP(&configPaths, "config", "c", nil, "set configuration file path")
	mainCommand.PersistentFlags().StringArrayVarP(&configDirectories, "config-directory", "C", nil, "set configuration directory path")
	mainCommand.PersistentFlags().StringVarP(&workingDir, "directory", "D", "", "set working directory")
	mainCommand.PersistentFlags().BoolVarP(&disableColor, "disable-color", "", false, "disable color output")
	mainCommand.PersistentFlags().StringVar(&logFile, "log-file", "", "write default logs to a private rotating file")
	mainCommand.PersistentFlags().Int64Var(&logMaxSize, "log-max-size", 2*1024*1024, "maximum bytes per log file")
	mainCommand.PersistentFlags().IntVar(&logMaxBackups, "log-max-backups", 3, "number of numbered log archives")
}

func preRun(cmd *cobra.Command, args []string) {
	globalCtx = context.Background()
	sudoUser := os.Getenv("SUDO_USER")
	sudoUID, _ := strconv.Atoi(os.Getenv("SUDO_UID"))
	sudoGID, _ := strconv.Atoi(os.Getenv("SUDO_GID"))
	if sudoUID == 0 && sudoGID == 0 && sudoUser != "" {
		sudoUserObject, _ := user.Lookup(sudoUser)
		if sudoUserObject != nil {
			sudoUID, _ = strconv.Atoi(sudoUserObject.Uid)
			sudoGID, _ = strconv.Atoi(sudoUserObject.Gid)
		}
	}
	if sudoUID > 0 && sudoGID > 0 {
		globalCtx = filemanager.WithDefault(globalCtx, "", "", sudoUID, sudoGID)
	}
	if logFile != "" {
		writer, err := log.NewRotatingWriter(globalCtx, logFile, logMaxSize, logMaxBackups)
		if err != nil {
			log.Fatal(err)
		}
		serviceLogWriter = writer
		logFactory := log.NewDefaultFactory(globalCtx, log.Formatter{
			BaseTime: time.Now(), DisableColors: true, FullTimestamp: true,
			TimestampFormat: "-0700 2006-01-02 15:04:05",
		}, writer, "", nil, false)
		common.Must(logFactory.Start())
		log.SetStdLogger(logFactory.Logger())
	} else if disableColor {
		logFactory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now(), DisableColors: true}, os.Stderr, "", nil, false)
		common.Must(logFactory.Start())
		log.SetStdLogger(logFactory.Logger())
	}
	if workingDir != "" {
		_, err := os.Stat(workingDir)
		if err != nil {
			filemanager.MkdirAll(globalCtx, workingDir, 0o777)
		}
		err = os.Chdir(workingDir)
		if err != nil {
			log.Fatal(err)
		}
	}
	if len(configPaths) == 0 && len(configDirectories) == 0 {
		configPaths = append(configPaths, "config.json")
	}
	globalCtx = include.Context(service.ContextWith(globalCtx, deprecated.NewStderrManager(log.StdLogger())))
}
