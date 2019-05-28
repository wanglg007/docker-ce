package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/docker/docker/cli"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/dockerversion"
	"github.com/docker/docker/pkg/reexec"
	"github.com/docker/docker/pkg/term"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newDaemonCommand() *cobra.Command {
	opts := newDaemonOptions(config.New())								//获取配置信息
	//docker daemon命令行对象
	cmd := &cobra.Command{
		Use:           "dockerd [OPTIONS]",								// 命令用法
		Short:         "A self-sufficient runtime for containers.",		// help时输出的命令提示信息
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cli.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {			// 命令的执行时的回调函数
			opts.flags = cmd.Flags()
			return runDaemon(opts)										// 接受命令行参数执行启动函数
		},
	}
	cli.SetupRootCommand(cmd)											// 为根命令设置usage, help等命令及错误处理

	flags := cmd.Flags()												// 新建一个flag(//解析命令)
	// 添加－v查看版本的参数
	flags.BoolVarP(&opts.version, "version", "v", false, "Print version information and quit")
	// 添加－config-file参数
	flags.StringVar(&opts.configFile, "config-file", defaultDaemonConfigFile, "Daemon configuration file")
	opts.InstallFlags(flags)
	installConfigFlags(opts.daemonConfig, flags)
	installServiceFlags(flags)

	return cmd
}

func runDaemon(opts *daemonOptions) error {								// 命令的执行方法
	if opts.version {
		showVersion()													// 打印出版本信息
		return nil
	}

	daemonCli := NewDaemonCli()											// 新建一个daemon CLI(创建daemon客户端对象)

	// Windows specific settings as these are not defaulted.
	if runtime.GOOS == "windows" {
		if opts.daemonConfig.Pidfile == "" {
			opts.daemonConfig.Pidfile = filepath.Join(opts.daemonConfig.Root, "docker.pid")
		}
		if opts.configFile == "" {
			opts.configFile = filepath.Join(opts.daemonConfig.Root, `config\daemon.json`)
		}
	}

	// On Windows, this may be launching as a service or with an option to
	// register the service.
	stop, runAsService, err := initService(daemonCli)
	if err != nil {
		logrus.Fatal(err)
	}

	if stop {
		return nil
	}

	// If Windows SCM manages the service - no need for PID files
	if runAsService {
		opts.daemonConfig.Pidfile = ""
	}

	err = daemonCli.start(opts)											// 启动daemon
	notifyShutdown(err)
	return err
}

func showVersion() {
	fmt.Printf("Docker version %s, build %s\n", dockerversion.Version, dockerversion.GitCommit)
}

func main() {
	if reexec.Init() {								//查看有没有注册的初始化函数，如果有，就直接返回
		return
	}

	// Set terminal emulation based on platform as required.
	_, stdout, stderr := term.StdStreams()

	// @jhowardmsft - maybe there is a historic reason why on non-Windows, stderr is used
	// here. However, on Windows it makes no sense and there is no need.
	if runtime.GOOS == "windows" {
		logrus.SetOutput(stdout)
	} else {
		logrus.SetOutput(stderr)
	}

	cmd := newDaemonCommand()						// 创建cmd
	cmd.SetOutput(stdout)
	if err := cmd.Execute(); err != nil {			// 执行cmd
		fmt.Fprintf(stderr, "%s\n", err)
		os.Exit(1)
	}
}
