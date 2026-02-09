package logger

import (
	"fmt"
	"strings"
)

var (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Purple = "\033[35m"
	Cyan   = "\033[36m"
	Gray   = "\033[37m"
	Bold   = "\033[1m"
)

// Info prints a blue [*] info message
func Info(format string, args ...interface{}) {
	fmt.Printf(Blue+"[*] "+Reset+format+"\n", args...)
}

// Success prints a green [+] success message
func Success(format string, args ...interface{}) {
	fmt.Printf(Green+"[+] "+Reset+format+"\n", args...)
}

// Warning prints a yellow [!] warning message
func Warning(format string, args ...interface{}) {
	fmt.Printf(Yellow+"[!] "+Reset+format+"\n", args...)
}

// Error prints a red [-] error message
func Error(format string, args ...interface{}) {
	fmt.Printf(Red+"[-] "+Reset+format+"\n", args...)
}

// Debug prints a gray [DEBUG] message
func Debug(format string, args ...interface{}) {
	fmt.Printf(Gray+"[DEBUG] "+Reset+format+"\n", args...)
}

// Section prints a cyan header for a new section
func Section(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	line := strings.Repeat("-", len(msg)+8)
	fmt.Printf("\n"+Cyan+Bold+"%s\n=== %s ===\n%s"+Reset+"\n", line, msg, line)
}

// SubStep prints a purple arrow -> message
func SubStep(format string, args ...interface{}) {
	fmt.Printf(Purple+"    -> "+Reset+format+"\n", args...)
}

// Command prints the command being executed in gray
func Command(cmd string) {
	fmt.Printf(Gray+"    $ %s"+Reset+"\n", cmd)
}
