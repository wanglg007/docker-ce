package parser // import "github.com/docker/docker/builder/dockerfile/parser"

import (
	"strings"
	"unicode"
)

// splitCommand takes a single line of text and parses out the cmd and args,
// which are used for dispatching to more exact parsing functions.
// splitCommand接受单行文本并解析cmd和args。这些用于调度到更精确的解析函数
func splitCommand(line string) (string, []string, string, error) {
	var args string
	var flags []string

	// Make sure we get the same results irrespective of leading/trailing spaces
	// 无论leading/trailing（前导/后缀）有多少的空格，都得确保得到相同的结果
	// Split将切片拆分为由表达式分隔的子字符串，并返回这些表达式匹配之间的子字符串切片;
	// TrimSpace返回字符串s的一部分，删除所有的leading/trailing（前导/后缀）空格;
	cmdline := tokenWhitespace.Split(strings.TrimSpace(line), 2)				// 2表示只有两个子字符串
	// cmdline[0]表示命令类型 如：groupadd         	//cmdline[1]表示命令参数 如：-f -g 842
	cmd := strings.ToLower(cmdline[0])

	if len(cmdline) == 2 {
		var err error
		args, flags, err = extractBuilderFlags(cmdline[1])							//解析BuilderFlags，并返回该行剩余部分
		if err != nil {
			return "", nil, "", err
		}
	}

	return cmd, flags, strings.TrimSpace(args), nil								//返回 cmd  选项  参数
}

func extractBuilderFlags(line string) (string, []string, error) {					//该函数就是解析剩下还有什么命令、选项、参数。
	// Parses the BuilderFlags and returns the remaining part of the line			//解析BuilderFlags，并返回该行剩余部分

	const (
		inSpaces = iota // looking for start of a word								//每次出现从0开始
		inWord
		inQuote
	)

	words := []string{}
	phase := inSpaces
	word := ""
	quote := '\000'
	blankOK := false
	var ch rune

	for pos := 0; pos <= len(line); pos++ {
		if pos != len(line) {
			ch = rune(line[pos])
		}

		if phase == inSpaces { // Looking for start of word
			if pos == len(line) { // end of input
				break
			}
			if unicode.IsSpace(ch) { // skip spaces
				continue
			}

			// Only keep going if the next word starts with --
			if ch != '-' || pos+1 == len(line) || rune(line[pos+1]) != '-' {
				return line[pos:], words, nil
			}

			phase = inWord // found something with "--", fall through
		}
		if (phase == inWord || phase == inQuote) && (pos == len(line)) {
			if word != "--" && (blankOK || len(word) > 0) {
				words = append(words, word)
			}
			break
		}
		if phase == inWord {
			if unicode.IsSpace(ch) {
				phase = inSpaces
				if word == "--" {
					return line[pos:], words, nil
				}
				if blankOK || len(word) > 0 {
					words = append(words, word)
				}
				word = ""
				blankOK = false
				continue
			}
			if ch == '\'' || ch == '"' {
				quote = ch
				blankOK = true
				phase = inQuote
				continue
			}
			if ch == '\\' {
				if pos+1 == len(line) {
					continue // just skip \ at end
				}
				pos++
				ch = rune(line[pos])
			}
			word += string(ch)
			continue
		}
		if phase == inQuote {
			if ch == quote {
				phase = inWord
				continue
			}
			if ch == '\\' {
				if pos+1 == len(line) {
					phase = inWord
					continue // just skip \ at end
				}
				pos++
				ch = rune(line[pos])
			}
			word += string(ch)
		}
	}

	return "", words, nil
}
