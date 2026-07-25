package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/tools"
)

var toolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "Manage and check external tools",
	Long:  "List, check, and manage the external security tools used by Chaathan.",
}

var toolsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tools and their categories",
	Run:   runToolsList,
}

var toolsCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check which tools are installed",
	Run:   runToolsCheck,
}

func init() {
	toolsCmd.AddCommand(toolsListCmd)
	toolsCmd.AddCommand(toolsCheckCmd)
	rootCmd.AddCommand(toolsCmd)
}

// ── Category metadata ────────────────────────────────────────────────────────

type categoryMeta struct {
	icon  string
	color string
}

var categoryStyles = map[string]categoryMeta{
	"Enum":     {"🔎", logger.BrightCyan},
	"DNS":      {"🌐", logger.BrightBlue},
	"Probe":    {"📡", logger.BrightGreen},
	"URLs":     {"🔗", logger.BrightPurple},
	"Crawl":    {"🕷️", logger.Purple},
	"Analysis": {"🧬", logger.Cyan},
	"Fuzz":     {"💥", logger.BrightYellow},
	"Vuln":     {"🛡️", logger.BrightRed},
	"Recon":    {"🔭", logger.Blue},
	"Cloud":    {"☁️", logger.BrightCyan},
	"Util":     {"🔧", logger.Gray},
	"Proxy":    {"🔄", logger.BrightYellow},
}

// ── Tools List ───────────────────────────────────────────────────────────────

func runToolsList(_ *cobra.Command, _ []string) {
	allTools := tools.GetAllTools()
	w := 52
	line := strings.Repeat("─", w)

	// Header box
	fmt.Printf("\n  %s╭%s╮%s\n", logger.Cyan+logger.Bold, line, logger.Reset)
	fmt.Printf("  %s│%s  🧰 %s%-46s%s %s│%s\n",
		logger.Cyan+logger.Bold, logger.Reset,
		logger.White+logger.Bold, "Chaathan Tool Suite", logger.Reset,
		logger.Cyan+logger.Bold, logger.Reset)
	fmt.Printf("  %s│%s  %s%-50s%s %s│%s\n",
		logger.Cyan+logger.Bold, logger.Reset,
		logger.Dim, fmt.Sprintf("%d tools • %d required", len(allTools), tools.CountRequired()), logger.Reset,
		logger.Cyan+logger.Bold, logger.Reset)
	fmt.Printf("  %s╰%s╯%s\n\n", logger.Cyan+logger.Bold, line, logger.Reset)

	// Group tools by category (preserve order)
	type catGroup struct {
		name      string
		toolInfos []tools.ToolInfo
	}
	var groups []catGroup
	seen := map[string]int{}

	for _, t := range allTools {
		if idx, ok := seen[t.Category]; ok {
			groups[idx].toolInfos = append(groups[idx].toolInfos, t)
		} else {
			seen[t.Category] = len(groups)
			groups = append(groups, catGroup{
				name:      t.Category,
				toolInfos: []tools.ToolInfo{t},
			})
		}
	}

	for _, g := range groups {
		meta := categoryStyles[g.name]
		fmt.Printf("  %s┌─%s %s %s%s%s\n",
			logger.Cyan, logger.Reset,
			meta.icon, meta.color+logger.Bold, g.name, logger.Reset)

		for _, t := range g.toolInfos {
			req := ""
			if t.Required {
				req = fmt.Sprintf(" %s[required]%s", logger.BrightYellow, logger.Reset)
			}
			fmt.Printf("  %s│%s  %-22s %s%s%s%s\n",
				logger.Dim, logger.Reset,
				t.Name,
				logger.Dim, t.Description, logger.Reset, req)
		}
		fmt.Println()
	}

	// Footer
	fmt.Printf("  %s%s%s\n", logger.Dim, strings.Repeat("━", 50), logger.Reset)
	fmt.Printf("  %s💡 Run 'chaathan tools check' to see installation status%s\n\n", logger.Dim, logger.Reset)
}

// ── Tools Check ──────────────────────────────────────────────────────────────

func runToolsCheck(_ *cobra.Command, _ []string) {
	allTools := tools.GetAllTools()
	w := 52
	line := strings.Repeat("─", w)

	// Header box
	fmt.Printf("\n  %s╭%s╮%s\n", logger.Cyan+logger.Bold, line, logger.Reset)
	fmt.Printf("  %s│%s  🔍 %s%-46s%s %s│%s\n",
		logger.Cyan+logger.Bold, logger.Reset,
		logger.White+logger.Bold, "Tool Installation Check", logger.Reset,
		logger.Cyan+logger.Bold, logger.Reset)
	fmt.Printf("  %s╰%s╯%s\n", logger.Cyan+logger.Bold, line, logger.Reset)

	installed := 0
	missing := 0
	missingRequired := 0

	// Group tools by category for display (preserve order)
	type toolResult struct {
		name     string
		required bool
		found    bool
		path     string
	}
	type catGroup struct {
		name    string
		results []toolResult
	}
	var groups []catGroup
	seen := map[string]int{}

	for _, t := range allTools {
		found, path := t.CheckStatus()

		result := toolResult{
			name:     t.Name,
			required: t.Required,
			found:    found,
			path:     path,
		}

		if found {
			installed++
		} else {
			missing++
			if t.Required {
				missingRequired++
			}
		}

		if idx, ok := seen[t.Category]; ok {
			groups[idx].results = append(groups[idx].results, result)
		} else {
			seen[t.Category] = len(groups)
			groups = append(groups, catGroup{
				name:    t.Category,
				results: []toolResult{result},
			})
		}
	}

	// Render each category
	for _, g := range groups {
		meta := categoryStyles[g.name]
		fmt.Printf("\n  %s┌─%s %s %s%s%s\n",
			logger.Cyan, logger.Reset,
			meta.icon, meta.color+logger.Bold, g.name, logger.Reset)

		for _, r := range g.results {
			if r.found {
				// Shorten path for display
				shortPath := r.path
				if len(shortPath) > 35 {
					shortPath = "…" + shortPath[len(shortPath)-34:]
				}
				fmt.Printf("  %s│%s  %s✓%s %-22s %s%s%s\n",
					logger.Dim, logger.Reset,
					logger.BrightGreen, logger.Reset,
					r.name,
					logger.Dim, shortPath, logger.Reset)
			} else {
				label := "missing"
				color := logger.Yellow
				icon := "○"
				if r.required {
					label = "MISSING (required)"
					color = logger.BrightRed
					icon = "✗"
				}
				fmt.Printf("  %s│%s  %s%s%s %-22s %s%s%s\n",
					logger.Dim, logger.Reset,
					color, icon, logger.Reset,
					r.name,
					color+logger.Dim, label, logger.Reset)
			}
		}
	}

	// ── Summary bar ──
	fmt.Println()
	fmt.Printf("  %s%s%s\n", logger.Dim, strings.Repeat("━", 50), logger.Reset)

	// Progress indicator
	total := len(allTools)
	pct := float64(installed) / float64(total) * 100
	barW := 20
	filled := int(float64(installed) / float64(total) * float64(barW))
	if filled > barW {
		filled = barW
	}

	barColor := logger.BrightGreen
	if pct < 50 {
		barColor = logger.BrightRed
	} else if pct < 80 {
		barColor = logger.BrightYellow
	}

	bar := barColor + strings.Repeat("━", filled) + logger.Reset +
		logger.Dim + strings.Repeat("╌", barW-filled) + logger.Reset

	fmt.Printf("  %s %s%d%s/%d tools  %s%.0f%%%s\n",
		bar,
		logger.Bold, installed, logger.Reset, total,
		barColor+logger.Bold, pct, logger.Reset)

	var parts []string
	if installed > 0 {
		parts = append(parts, fmt.Sprintf("%s✓ %d installed%s", logger.BrightGreen, installed, logger.Reset))
	}
	if missing > 0 && missingRequired == 0 {
		parts = append(parts, fmt.Sprintf("%s○ %d optional missing%s", logger.Yellow, missing, logger.Reset))
	}
	if missingRequired > 0 {
		parts = append(parts, fmt.Sprintf("%s✗ %d required missing%s", logger.BrightRed, missingRequired, logger.Reset))
	}
	fmt.Printf("  %s\n", strings.Join(parts, "  "))
	fmt.Printf("  %s%s%s\n", logger.Dim, strings.Repeat("━", 50), logger.Reset)

	// Status message
	if missingRequired > 0 {
		fmt.Printf("\n  %s✗%s %s%d required tool(s) missing!%s\n", logger.BrightRed, logger.Reset, logger.Red, missingRequired, logger.Reset)
		fmt.Printf("  %s💡 Run: %schaathan setup%s\n\n", logger.Dim, logger.Reset+logger.BrightCyan, logger.Reset)
	} else if missing > 0 {
		fmt.Printf("\n  %s⚠%s %s%d optional tool(s) missing.%s\n", logger.BrightYellow, logger.Reset, logger.Yellow, missing, logger.Reset)
		fmt.Printf("  %s💡 Run '%schaathan setup%s%s' to install all.%s\n\n", logger.Dim, logger.Reset+logger.BrightCyan, logger.Reset, logger.Dim, logger.Reset)
	} else {
		fmt.Printf("\n  %s✓%s %sAll tools installed! You're good to go.%s 🚀\n\n", logger.BrightGreen, logger.Reset, logger.BrightGreen, logger.Reset)
	}
}
