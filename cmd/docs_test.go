package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// The docs check: every `envisible ...` command line written in the README, the
// setup skill and AGENTS.md is resolved against the real command tree, so a
// command or flag that no longer exists fails the build instead of failing the
// reader. Nothing is executed and no flag value is set; this only asks "does
// this subcommand exist, and does it define this flag".
//
// It exists because `run -e` was removed in v0.0.3 and stayed in the README and
// in twelve places in the skill for eight months.

// checkedDocs are the files whose commands must be valid today. CHANGELOG.md is
// deliberately absent: it describes old releases and may name removed flags.
var checkedDocs = []string{"README.md", "AGENTS.md", filepath.Join("skills", "envisible", "SKILL.md")}

// docCommand is one `envisible ...` invocation found in a document.
type docCommand struct {
	file string
	line int
	args []string // tokens after "envisible", up to the end of that command
	// strict is true when the text is unmistakably a command (it starts a code
	// span or sits at a shell command position). When false, "envisible" is
	// followed by an arbitrary word inside code (a YAML step name, a comment),
	// so an unknown first word is treated as prose rather than as a typo.
	strict bool
}

var (
	inlineCodeRE = regexp.MustCompile("`([^`]+)`")
	// The program as the docs spell it: the binary, or `go run .` in AGENTS.md.
	programRE = regexp.MustCompile(`(^|[\s|;&("'` + "`" + `])(envisible|go run \.)\s+`)
	// Leading `NAME=value ` environment assignments and a `$ ` prompt.
	envPrefixRE = regexp.MustCompile(`^(\$\s+)?([A-Za-z_][A-Za-z0-9_]*=\S*\s+)*$`)
	// Text that ends at a position where the shell starts a new command.
	cmdPositionRE = regexp.MustCompile(`(\||&&|\|\||;|\$\(|--|\bdo|\bthen|\bif|!)\s*$`)
	redirectRE    = regexp.MustCompile(`^\d*[<>]`)
	// <file>, <envfile>: a value the reader supplies, not a redirect.
	anglePlaceholderRE = regexp.MustCompile(`^<[^<>\s]+>`)
)

// extractDocCommands finds the envisible invocations in markdown: every line of
// a fenced code block, and every inline code span outside one.
func extractDocCommands(file, markdown string) []docCommand {
	var out []docCommand
	inFence := false
	for i, line := range strings.Split(markdown, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence {
			out = append(out, commandsInCode(file, i+1, line, false)...)
			continue
		}
		for _, m := range inlineCodeRE.FindAllStringSubmatch(line, -1) {
			out = append(out, commandsInCode(file, i+1, m[1], true)...)
		}
	}
	return out
}

// commandsInCode returns each envisible invocation inside one piece of code.
func commandsInCode(file string, line int, code string, inline bool) []docCommand {
	var out []docCommand
	for _, loc := range programRE.FindAllStringSubmatchIndex(code, -1) {
		before := code[:loc[4]] // everything ahead of the program name
		rest := code[loc[1]:]
		lead := strings.TrimSpace(before)
		strict := envPrefixRE.MatchString(strings.TrimLeft(before, " \t")) || cmdPositionRE.MatchString(lead)
		if args := commandTokens(rest); len(args) > 0 {
			out = append(out, docCommand{file: file, line: line, args: args, strict: strict})
		}
	}
	return out
}

// commandTokens splits the text after the program name into arguments, stopping
// where that command ends: a pipe, a list operator, a redirect, a comment, or
// the close of a `$(...)`.
func commandTokens(s string) []string {
	var args []string
	for _, tok := range strings.Fields(s) {
		switch {
		// `\|` is a pipe escaped for a markdown table cell.
		case tok == "|", tok == `\|`, tok == "||", tok == "&&", tok == ";", tok == "&", tok == `\`:
			return args
		case strings.HasPrefix(tok, "#"):
			return args
		// `> out` and `2>/dev/null` end the command; `<file>` is an argument.
		case redirectRE.MatchString(tok) && !anglePlaceholderRE.MatchString(tok):
			return args
		}
		// `envisible check "$f"; done` and `$(envisible decrypt --strip f)`. A
		// token that opens its own `$(` keeps its closing parenthesis.
		cutset := ";)"
		if strings.Contains(tok, "$(") {
			cutset = ";"
		}
		if cut := strings.IndexAny(tok, cutset); cut >= 0 {
			if cut > 0 {
				args = append(args, tok[:cut])
			}
			return args
		}
		args = append(args, tok)
	}
	return args
}

// isPlaceholder reports whether a documented argument stands for a value the
// reader supplies: <file>, {gcp,aws,azure}, [command], "$f", ...
func isPlaceholder(tok string) bool {
	tok = strings.Trim(tok, `"'`)
	return tok == "..." || tok == "…" || strings.HasPrefix(tok, "<") || strings.HasPrefix(tok, "{") ||
		strings.HasPrefix(tok, "[") || strings.HasPrefix(tok, "$")
}

// lookupFlag finds a flag by long name or one-character shorthand among the
// flags c accepts: its own, its persistent ones, and those it inherits.
func lookupFlag(c *cobra.Command, name string, short bool) *pflag.Flag {
	c.InitDefaultHelpFlag()
	for _, fs := range []*pflag.FlagSet{c.Flags(), c.PersistentFlags(), c.InheritedFlags()} {
		var f *pflag.Flag
		if short {
			f = fs.ShorthandLookup(name)
		} else {
			f = fs.Lookup(name)
		}
		if f != nil {
			return f
		}
	}
	return nil
}

func subcommand(c *cobra.Command, name string) *cobra.Command {
	for _, sub := range c.Commands() {
		if sub.Name() == name || sub.HasAlias(name) {
			return sub
		}
	}
	return nil
}

// validateDocCommand resolves a documented invocation against root. It returns
// "" when the invocation is valid (or is prose, in non-strict mode), and a
// description of the problem otherwise.
func validateDocCommand(root *cobra.Command, dc docCommand) string {
	cur := root
	for i := 0; i < len(dc.args); i++ {
		tok := strings.TrimRight(dc.args[i], "\"',.:`")
		switch {
		case tok == "--":
			return ""
		case tok == "-" || tok == "":
			// A bare "-" is the stdin target, a positional.
		case strings.HasPrefix(tok, "--"):
			name, _, hasValue := strings.Cut(tok[2:], "=")
			f := lookupFlag(cur, name, false)
			if f == nil {
				return fmt.Sprintf("unknown flag --%s for %q", name, cur.CommandPath())
			}
			if !hasValue && f.Value.Type() != "bool" {
				i++ // the next token is this flag's value
			}
		case strings.HasPrefix(tok, "-"):
			// One or more shorthands: -i, -iq, -f.env, or -f followed by a value.
			for j := 1; j < len(tok); j++ {
				f := lookupFlag(cur, tok[j:j+1], true)
				if f == nil {
					return fmt.Sprintf("unknown shorthand flag -%s for %q", tok[j:j+1], cur.CommandPath())
				}
				if f.Value.Type() != "bool" {
					if j == len(tok)-1 {
						i++ // value is the next token
					}
					break // otherwise the rest of this token is the value
				}
			}
		case cur.HasSubCommands():
			if sub := subcommand(cur, tok); sub != nil {
				cur = sub
				continue
			}
			if tok == "help" || tok == "completion" || isPlaceholder(tok) {
				return "" // cobra built-ins, or `envisible <command> --help`
			}
			if !dc.strict && cur == root {
				return "" // "Restore envisible key": prose inside a code block
			}
			return fmt.Sprintf("unknown command %q for %q", tok, cur.CommandPath())
		case cur == runCmd:
			// Flag parsing stops at the command `run` launches; the rest is the
			// child's own arguments.
			return ""
		}
	}
	return ""
}

func (dc docCommand) String() string {
	return fmt.Sprintf("%s:%d: envisible %s", dc.file, dc.line, strings.Join(dc.args, " "))
}

func TestDocumentedCommandsExist(t *testing.T) {
	repoRoot := filepath.Dir(testPkgDir)
	for _, rel := range checkedDocs {
		data, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		commands := extractDocCommands(rel, string(data))
		// A document that yields no commands means the extractor broke, not that
		// the document is clean. Each of these has well over this many.
		if len(commands) < 3 {
			t.Errorf("%s: found only %d envisible command(s); the extractor is not seeing them", rel, len(commands))
		}
		for _, dc := range commands {
			if problem := validateDocCommand(rootCmd, dc); problem != "" {
				t.Errorf("%s\n\t%s", dc, problem)
			}
		}
		t.Logf("%s: %d command(s) checked", rel, len(commands))
	}
}

// TestDocsCheckCatchesInvalidCommands proves the checker itself: each bad line
// is reported, and each good or merely prose-like line is not. Without this the
// test above could pass by recognizing nothing.
func TestDocsCheckCatchesInvalidCommands(t *testing.T) {
	fence := "```"
	cases := []struct {
		name     string
		markdown string
		want     string // substring of the reported problem, or "" for no problem
	}{
		// The regression: removed in v0.0.3, documented until 2026-10.
		{"removed shorthand in a fenced block", fence + "bash\nenvisible run -e .env -- npm start\n" + fence, `unknown shorthand flag -e for "envisible run"`},
		{"removed shorthand in an inline span", "Use `envisible run -e <envfile> -- <cmd>`.", "unknown shorthand flag -e"},
		{"removed shorthand in a YAML step", fence + "yaml\n  run: envisible run -e .env.test -- npm test\n" + fence, "unknown shorthand flag -e"},
		{"removed shorthand in a JSON script", fence + "json\n    \"start\": \"envisible run -e .env -- node server.js\",\n" + fence, "unknown shorthand flag -e"},
		{"removed shorthand after an env assignment", "`ENVISIBLE_KEY=<base64> envisible run -e <envfile> -- <cmd>`", "unknown shorthand flag -e"},
		{"unknown long flag", "`envisible decrypt --plain file.env`", `unknown flag --plain for "envisible decrypt"`},
		{"unknown subcommand", "`envisible rotate file.env`", `unknown command "rotate" for "envisible"`},
		{"unknown nested subcommand", "`envisible kms destroy`", `unknown command "destroy" for "envisible kms"`},
		{"a flag that belongs to another command", "`envisible encrypt --strip f`", "unknown flag --strip"},
		{"bad command after a pipe", fence + "\ncat secrets.json | envisible set .env --from-yaml -\n" + fence, "unknown flag --from-yaml"},
		{"bad command inside $( )", fence + "\nVAR=$(envisible decrypt --stripped f)\n" + fence, "unknown flag --stripped"},
		{"go run . is the same program", "`go run . keygenerate`", `unknown command "keygenerate"`},
		{"bad flag after a <placeholder>", "`envisible decrypt <file> --plain`", "unknown flag --plain"},
		{"bad flag after a placeholder value", "`envisible kms init --resource <ref> --providr aws`", "unknown flag --providr"},
		{"bad flag before a table-escaped pipe", "| Generate | `envisible keygen --print \\| <store>` |", "unknown flag --print"},

		{"valid run", "`envisible run -f .env -- npm start`", ""},
		{"the child's flags are not envisible's", "`envisible run ruby -e 'puts 1'`", ""},
		{"flags after -- are the child's", "`envisible run -- node --inspect -e x`", ""},
		{"global flag before the subcommand", "`envisible -q decrypt --strip f`", ""},
		{"flag with a value, then a flag", "`envisible kms init --provider aws --resource <ref>`", ""},
		{"combined bool shorthands", "`envisible -q encrypt -i f`", ""},
		{"stdin target", "`envisible check -`", ""},
		{"placeholder subcommand", "`envisible <command> --help`", ""},
		{"help flag", "`envisible run --help`", ""},
		{"pipe ends the command", fence + "\nenvisible decrypt --strip f | diff - --unknown-diff-flag x\n" + fence, ""},
		{"redirect ends the command", fence + "\nenvisible decrypt --strip f > out --not-ours\n" + fence, ""},
		{"comment ends the command", fence + "\nenvisible keygen   # --not-a-flag here\n" + fence, ""},
		{"table-escaped pipe ends the command", "| Generate | `envisible keygen --print-key \\| store --put-flag` |", ""},
		{"a list separator ends the command", fence + "\nfor f in *.env; do envisible check \"$f\"; done --not-ours\n" + fence, ""},
		{"input redirect ends the command", fence + "\nenvisible set .env KEY - < secret.txt --not-ours\n" + fence, ""},
		{"prose inside a code block", fence + "yaml\n- name: Restore envisible key\n" + fence, ""},
		{"file names are not commands", "`envisible.key` and `envisible.pub`", ""},
		{"prose outside code is ignored", "Then envisible frobnicate --everything.", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var problems []string
			commands := extractDocCommands("doc.md", tc.markdown)
			for _, dc := range commands {
				if p := validateDocCommand(rootCmd, dc); p != "" {
					problems = append(problems, p)
				}
			}
			got := strings.Join(problems, "; ")
			switch {
			case tc.want == "" && got != "":
				t.Errorf("reported a problem for valid text: %s", got)
			case tc.want != "" && !strings.Contains(got, tc.want):
				t.Errorf("problems = %q, want one containing %q (commands found: %v)", got, tc.want, commands)
			}
		})
	}
}
