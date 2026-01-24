package ui

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
)

var (
	// Colors
	green  = lipgloss.Color("2")
	red    = lipgloss.Color("1")
	blue   = lipgloss.Color("4")
	gray   = lipgloss.Color("8")
	yellow = lipgloss.Color("3")

	// Styles
	successStyle = lipgloss.NewStyle().Foreground(green).Bold(true)
	errorStyle   = lipgloss.NewStyle().Foreground(red).Bold(true)
	infoStyle    = lipgloss.NewStyle().Foreground(blue).Bold(true)
	warnStyle    = lipgloss.NewStyle().Foreground(yellow).Bold(true)
	labelStyle   = lipgloss.NewStyle().Foreground(gray)
	valueStyle   = lipgloss.NewStyle().Bold(true)

	// Icons
	checkMark = successStyle.Render("✔")
	crossMark = errorStyle.Render("✖")
	infoIcon  = infoStyle.Render("ℹ")
	warnIcon  = warnStyle.Render("⚠")
)

// Success prints a success message with a checkmark
func Success(msg string, args ...interface{}) {
	fmt.Printf("%s %s\n", checkMark, fmt.Sprintf(msg, args...))
}

// Error prints an error message with a cross mark
func Error(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s %s\n", crossMark, errorStyle.Render(fmt.Sprintf(msg, args...)))
}

// Info prints an informational message
func Info(msg string, args ...interface{}) {
	fmt.Printf("%s %s\n", infoIcon, fmt.Sprintf(msg, args...))
}

// Warn prints a warning message
func Warn(msg string, args ...interface{}) {
	fmt.Printf("%s %s\n", warnIcon, warnStyle.Render(fmt.Sprintf(msg, args...)))
}

// KV prints a key-value pair with consistent styling
func KV(key, value string) {
	fmt.Printf("  %s %s\n", labelStyle.Render(key+":"), valueStyle.Render(value))
}

// Headline prints a bold headline
func Headline(msg string) {
	style := lipgloss.NewStyle().Bold(true).Underline(true).MarginBottom(1)
	fmt.Println(style.Render(msg))
}
