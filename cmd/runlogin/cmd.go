package main

import (
	"fmt"
	"io"
	"os"
	"path"
)

type Command interface {
	Name() string
	Help(w io.Writer)
	Run(w io.Writer, args []string)
}

type HelpCmd struct{}
type ListCmd struct{}
type CatCmd struct{}
type ExitCmd struct{}

func (cmd *HelpCmd) Name() string {
	return "help"
}

func (cmd *HelpCmd) Help(w io.Writer) {
	fmt.Fprintln(w, `NAME
	help -- give help for a command
SYNOPSIS
	help command
DESCRIPTION
	The help command displays help for a command.`)
}

func (cmd *HelpCmd) Run(w io.Writer, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(w, `Valid commands:
			ls   cat   exit   help
		`)
		return
	}

	helpCmd := Lookup(args[0])
	if helpCmd == nil {
		fmt.Fprintln(w, "Unknown command:", args[0])
	} else {
		helpCmd.Help(w)
	}

}

func (cmd *ListCmd) Name() string {
	return "ls"
}

func (cmd *ListCmd) Help(w io.Writer) {
	fmt.Fprintln(w, `NAME
	ls -- list content of current directory
SYNOPSIS
	ls [directory]
DESCRIPTION
	The ls command shows all files and directories in working directory`)
}

func (cmd *ListCmd) Run(w io.Writer, args []string) {
	entries, _ := storage.ReadDir("data")
	for _, entry := range entries {
		fmt.Println(entry.Name())
	}
	fmt.Println()
}

func (cmd *CatCmd) Name() string {
	return "cat"
}

func (cmd *CatCmd) Help(w io.Writer) {
	fmt.Fprintln(w, `NAME
	cat -- concatenate and print files
SYNOPSIS
	cat [file ...]
DESCRIPTION
	The cat utility reads files sequentually and write them to standard output.`)
}

func (cmd *CatCmd) Run(w io.Writer, args []string) {
	if len(args) < 1 {
		fmt.Println("Missing file argument")
	} else {
		for _, arg := range args {
			filepath := path.Join("data", arg)
			content, err := storage.ReadFile(filepath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Could not read file:", err)
			}
			fmt.Println(string(content))
		}
	}
}

func (cmd *ExitCmd) Name() string {
	return "exit"
}

func (cmd *ExitCmd) Help(w io.Writer) {
	fmt.Fprintln(w, `NAME
	exit -- exit the shell
SYNOPSIS
	exit
DESCRIPTION
	exit the mainframe shell. Logs the user out.`)
}

func (cmd *ExitCmd) Run(w io.Writer, args []string) {
	os.Exit(0)
}

var commands = [...]Command{
	new(HelpCmd),
	new(ListCmd),
	new(CatCmd),
	new(ExitCmd),
}

// Lookup command with given name. Returns nil if command
// of that name is not found
func Lookup(cmdName string) Command {
	for _, cmd := range commands {
		if cmd.Name() == cmdName {
			return cmd
		}
	}
	return nil
}
