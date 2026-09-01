package uci

import "strings"

// Command is one UCI command: one call a caller makes as
// execx.Runner.Run("uci", cmd.Args...). See the package doc "Command
// representation" for why Args, not text, is the primary form.
type Command struct {
	// Args is the argument list, in the exact order and form
	// execx.Runner.Run expects them: unexpanded, unquoted, never
	// passed through a shell.
	Args []string
}

// Batch is an ordered list of Command values. Order matters: it is
// the exact sequence a caller must run the commands in, and the exact
// sequence an integration test asserts (PLAN.md stage 3 item 12). See
// the package doc "Ordering".
type Batch []Command

// Text renders b as one line per command, "uci" followed by its
// Args joined with a single space, terminated with "\n". It exists
// only so this package's own tests can compare a built Batch against
// a golden text file; see the package doc "Command representation"
// for why nothing parses Text back into a Batch.
func (b Batch) Text() string {
	var sb strings.Builder
	for _, cmd := range b {
		sb.WriteString("uci")
		for _, arg := range cmd.Args {
			sb.WriteByte(' ')
			sb.WriteString(arg)
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

// setCmd returns the Command that sets one option, or one list
// element, to value: "uci set <config>.<section>.<option>=<value>".
// config is the UCI config file the section lives in ("network" for
// every function in this file's original callers, "firewall" for the
// stunmesh zone; see firewall.go).
func setCmd(config, section, option, value string) Command {
	return Command{Args: []string{"set", config + "." + section + "." + option + "=" + value}}
}

// createCmd returns the Command that creates section with the given
// UCI type: "uci set <config>.<section>=<typ>".
func createCmd(config, section, typ string) Command {
	return Command{Args: []string{"set", config + "." + section + "=" + typ}}
}

// addListCmd returns the Command that appends one value to a UCI
// list option: "uci add_list <config>.<section>.<option>=<value>".
func addListCmd(config, section, option, value string) Command {
	return Command{Args: []string{"add_list", config + "." + section + "." + option + "=" + value}}
}

// delListCmd returns the Command that removes one value from a UCI
// list option: "uci del_list <config>.<section>.<option>=<value>".
// Unlike deleteCmd, it removes only the named value; every other
// value in the list, and the section itself, is left untouched.
func delListCmd(config, section, option, value string) Command {
	return Command{Args: []string{"del_list", config + "." + section + "." + option + "=" + value}}
}

// deleteCmd returns the Command that deletes section entirely:
// "uci delete <config>.<section>".
func deleteCmd(config, section string) Command {
	return Command{Args: []string{"delete", config + "." + section}}
}
