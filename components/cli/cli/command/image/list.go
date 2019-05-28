package image

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/formatter"
	"github.com/docker/cli/opts"
	"github.com/docker/docker/api/types"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

type imagesOptions struct {
	matchName string

	quiet       bool
	all         bool
	noTrunc     bool
	showDigests bool
	format      string
	filter      opts.FilterOpt
}

// NewImagesCommand creates a new `docker images` command
func NewImagesCommand(dockerCli command.Cli) *cobra.Command {
	options := imagesOptions{filter: opts.NewFilterOpt()}			// images命令需要的所有参数，不同的命令的options不同

	cmd := &cobra.Command{
		Use:   "images [OPTIONS] [REPOSITORY[:TAG]]",
		Short: "List images",
		Args:  cli.RequiresMaxArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				options.matchName = args[0]
			}
			return runImages(dockerCli, options)					// 真正的执行方法
		},
	}

	flags := cmd.Flags()
	// 将参数解析的结果，放到options
	flags.BoolVarP(&options.quiet, "quiet", "q", false, "Only show numeric IDs")
	flags.BoolVarP(&options.all, "all", "a", false, "Show all images (default hides intermediate images)")
	flags.BoolVar(&options.noTrunc, "no-trunc", false, "Don't truncate output")
	flags.BoolVar(&options.showDigests, "digests", false, "Show digests")
	flags.StringVar(&options.format, "format", "", "Pretty-print images using a Go template")
	flags.VarP(&options.filter, "filter", "f", "Filter output based on conditions provided")

	return cmd
}

func newListCommand(dockerCli command.Cli) *cobra.Command {
	cmd := *NewImagesCommand(dockerCli)
	cmd.Aliases = []string{"images", "list"}
	cmd.Use = "ls [OPTIONS] [REPOSITORY[:TAG]]"
	return &cmd
}

func runImages(dockerCli command.Cli, options imagesOptions) error {
	ctx := context.Background()										// go语言的context包的功能

	filters := options.filter.Value()								// 获取用户输入--fiter的内容
	if options.matchName != "" {									// 用户输入的arg
		filters.Add("reference", options.matchName)
	}

	listOptions := types.ImageListOptions{							// 用户输入的-a参数
		All:     options.all,
		Filters: filters,
	}

	images, err := dockerCli.Client().ImageList(ctx, listOptions)	// 通过此Client访问deamon，拿到镜像列表
	if err != nil {
		return err
	}

	format := options.format										// 用户输入的--format参数
	if len(format) == 0 {
		// 如果无用户输入的format，则读取配置文件中的配置，且非静默模式（-q）,否则使用静默模式的format
		if len(dockerCli.ConfigFile().ImagesFormat) > 0 && !options.quiet {
			format = dockerCli.ConfigFile().ImagesFormat
		} else {
			format = formatter.TableFormatKey
		}
	}

	imageCtx := formatter.ImageContext{
		Context: formatter.Context{
			Output: dockerCli.Out(),														// 输出配置
			Format: formatter.NewImageFormat(format, options.quiet, options.showDigests),	// 格式信息
			Trunc:  !options.noTrunc,														// 用户输入的--no-trunc信息，意思为全量打印
		},
		Digest: options.showDigests,														// 用户输入的--digests 是否显示摘要信息
	}
	return formatter.ImageWrite(imageCtx, images)											// 具体的格式化打印细节
}
