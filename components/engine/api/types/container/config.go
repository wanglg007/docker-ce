package container // import "github.com/docker/docker/api/types/container"

import (
	"time"

	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/go-connections/nat"
)

// MinimumDuration puts a minimum on user configured duration.
// This is to prevent API error on time unit. For example, API may
// set 3 as healthcheck interval with intention of 3 seconds, but
// Docker interprets it as 3 nanoseconds.
const MinimumDuration = 1 * time.Millisecond

// HealthConfig holds configuration settings for the HEALTHCHECK feature.
type HealthConfig struct {
	// Test is the test to perform to check that the container is healthy.
	// An empty slice means to inherit the default.
	// The options are:
	// {} : inherit healthcheck
	// {"NONE"} : disable healthcheck
	// {"CMD", args...} : exec arguments directly
	// {"CMD-SHELL", command} : run command with system's default shell
	Test []string `json:",omitempty"`

	// Zero means to inherit. Durations are expressed as integer nanoseconds.
	Interval    time.Duration `json:",omitempty"` // Interval is the time to wait between checks.
	Timeout     time.Duration `json:",omitempty"` // Timeout is the time to wait before considering the check to have hung.
	StartPeriod time.Duration `json:",omitempty"` // The start period for the container to initialize before the retries starts to count down.

	// Retries is the number of consecutive failures needed to consider a container as unhealthy.
	// Zero means inherit.
	Retries int `json:",omitempty"`
}

// Config contains the configuration data about a container.			描述DOCKER容器本身的属性信息
// It should hold only portable information about the container.
// Here, "portable" means "independent from the host we are running on".
// Non-portable information *should* appear in HostConfig.
// All fields added to this struct must be marked `omitempty` to keep getting
// predictable hashes from the old `v1Compatibility` configuration.
type Config struct {					// 包含着容器的配置数据，主要是与主机无关的配置数据，比如hostname，user;
	Hostname        string              // Hostname			容器内的主机名
	Domainname      string              // Domainname		域名服务器名称
	User            string              // User that will run the command(s) inside the container, also support user:group	容器内用户名
	AttachStdin     bool                // Attach the standard input, makes possible user interaction
	AttachStdout    bool                // Attach the standard output														是否附加标准输出
	AttachStderr    bool                // Attach the standard error
	ExposedPorts    nat.PortSet         `json:",omitempty"` // List of exposed ports										容器内暴露的端口号
	Tty             bool                // Attach standard streams to a tty, including stdin if it is not closed.			是否分配一个伪终端
	OpenStdin       bool                // Open stdin		在没有附加标准输入时，是否依然打开标准输入
	StdinOnce       bool                // If true, close stdin after the 1 attached client disconnects.					如该为真，用户关闭标准输入，容器的标准输入关闭
	Env             []string            // List of environment variable to set in the container								环境变量
	Cmd             strslice.StrSlice   // Command to run when starting the container										容器内运行的指令
	Healthcheck     *HealthConfig       `json:",omitempty"` // Healthcheck describes how to check the container is healthy
	ArgsEscaped     bool                `json:",omitempty"` // True if command is already escaped (Windows specific)
	Image           string              // Name of the image as it was passed by the operator (e.g. could be symbolic)		镜像名称
	Volumes         map[string]struct{} // List of volumes (mounts) used for the container									挂载目录
	WorkingDir      string              // Current directory (PWD) in the command will be launched							进程指定的工作目录
	Entrypoint      strslice.StrSlice   // Entrypoint to run when starting the container									覆盖镜像中默认的entrypoint
	NetworkDisabled bool                `json:",omitempty"` // Is network disabled											是否关闭容器网络功能
	MacAddress      string              `json:",omitempty"` // Mac Address of the container									MAC地址
	OnBuild         []string            // ONBUILD metadata that were defined on the image Dockerfile
	Labels          map[string]string   // List of labels set to this container
	StopSignal      string              `json:",omitempty"` // Signal to stop a container
	StopTimeout     *int                `json:",omitempty"` // Timeout (in seconds) to stop a container
	Shell           strslice.StrSlice   `json:",omitempty"` // Shell for shell-form of RUN, CMD, ENTRYPOINT
}
