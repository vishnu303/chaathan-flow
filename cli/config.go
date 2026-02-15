package cli

import (
	"fmt"
	"github.com/vishnu303/chaathan-flow/pkg/config"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"os"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage Chaathan configuration",
	Long:  `View, edit, or reset the Chaathan configuration file.`,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Run:   runConfigShow,
}

var configEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Open configuration file in editor",
	Run:   runConfigEdit,
}

var configResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset configuration to defaults",
	Run:   runConfigReset,
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Show configuration file path",
	Run:   runConfigPath,
}

var configSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a configuration value",
	Long: `Set a configuration value. Examples:
  chaathan config set api_keys.github ghp_xxxxx
  chaathan config set general.verbose true
  chaathan config set notifications.discord_webhook https://discord.com/api/webhooks/xxx`,
	Args: cobra.ExactArgs(2),
	Run:  runConfigSet,
}

func init() {
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configEditCmd)
	configCmd.AddCommand(configResetCmd)
	configCmd.AddCommand(configPathCmd)
	configCmd.AddCommand(configSetCmd)
	rootCmd.AddCommand(configCmd)
}

func runConfigShow(cmd *cobra.Command, args []string) {
	cfgPath := config.GetDefaultConfigPath()

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warning("No configuration file found. Creating default...")
			_, err = config.LoadOrCreate(cfgPath)
			if err != nil {
				logger.Error("Failed to create config: %v", err)
				return
			}
			data, _ = os.ReadFile(cfgPath)
		} else {
			logger.Error("Failed to read config: %v", err)
			return
		}
	}

	fmt.Println(string(data))
}

func runConfigEdit(cmd *cobra.Command, args []string) {
	cfgPath := config.GetDefaultConfigPath()

	// Ensure config exists
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		logger.Info("Creating default configuration...")
		if _, err := config.LoadOrCreate(cfgPath); err != nil {
			logger.Error("Failed to create config: %v", err)
			return
		}
	}

	// Determine editor
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		switch runtime.GOOS {
		case "windows":
			editor = "notepad"
		case "darwin":
			editor = "nano"
		default:
			editor = "vim"
		}
	}

	logger.Info("Opening config in %s...", editor)

	c := exec.Command(editor, cfgPath)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	if err := c.Run(); err != nil {
		logger.Error("Failed to open editor: %v", err)
		logger.Info("Config file location: %s", cfgPath)
	}
}

func runConfigReset(cmd *cobra.Command, args []string) {
	cfgPath := config.GetDefaultConfigPath()

	logger.Warning("This will reset your configuration to defaults.")
	logger.Warning("Your current config will be backed up.")

	// Backup existing config
	if _, err := os.Stat(cfgPath); err == nil {
		backupPath := cfgPath + ".backup"
		if err := os.Rename(cfgPath, backupPath); err != nil {
			logger.Error("Failed to backup config: %v", err)
			return
		}
		logger.Info("Backed up to: %s", backupPath)
	}

	// Create new default config
	cfg := config.DefaultConfig()
	if err := config.Save(cfg, cfgPath); err != nil {
		logger.Error("Failed to create config: %v", err)
		return
	}

	logger.Success("Configuration reset to defaults!")
	logger.Info("Config file: %s", cfgPath)
}

func runConfigPath(cmd *cobra.Command, args []string) {
	fmt.Println(config.GetDefaultConfigPath())
}

func runConfigSet(cmd *cobra.Command, args []string) {
	key := args[0]
	value := args[1]

	cfgPath := config.GetDefaultConfigPath()

	// Load or create config
	cfg, err := config.LoadOrCreate(cfgPath)
	if err != nil {
		logger.Error("Failed to load config: %v", err)
		return
	}

	// Set value based on key
	switch key {
	case "api_keys.github":
		cfg.APIKeys.GitHub = value
	case "api_keys.shodan":
		cfg.APIKeys.Shodan = value
	case "api_keys.securitytrails":
		cfg.APIKeys.SecurityTrails = value
	case "api_keys.virustotal":
		cfg.APIKeys.VirusTotal = value
	case "api_keys.chaos":
		cfg.APIKeys.Chaos = value
	case "general.verbose":
		cfg.General.Verbose = value == "true"
	case "general.mode":
		cfg.General.Mode = value
	case "general.output_dir":
		cfg.General.OutputDir = value
	case "notifications.discord_webhook":
		cfg.Notifications.DiscordWebhook = value
		cfg.Notifications.Enabled = true
	case "notifications.slack_webhook":
		cfg.Notifications.SlackWebhook = value
		cfg.Notifications.Enabled = true
	case "notifications.telegram_bot_token":
		cfg.Notifications.TelegramBotToken = value
	case "notifications.telegram_chat_id":
		cfg.Notifications.TelegramChatID = value
	case "notifications.enabled":
		cfg.Notifications.Enabled = value == "true"
	case "notifications.min_severity":
		cfg.Notifications.MinSeverity = value
	default:
		logger.Error("Unknown config key: %s", key)
		logger.Info("Available keys:")
		logger.Info("  api_keys.github, api_keys.shodan, api_keys.securitytrails")
		logger.Info("  api_keys.virustotal, api_keys.chaos")
		logger.Info("  general.verbose, general.mode, general.output_dir")
		logger.Info("  notifications.discord_webhook, notifications.slack_webhook")
		logger.Info("  notifications.telegram_bot_token, notifications.telegram_chat_id")
		logger.Info("  notifications.enabled, notifications.min_severity")
		return
	}

	// Save config
	if err := config.Save(cfg, cfgPath); err != nil {
		logger.Error("Failed to save config: %v", err)
		return
	}

	logger.Success("Set %s = %s", key, maskSecret(key, value))
}

func maskSecret(key, value string) string {
	// Mask sensitive values
	if len(value) > 8 && (contains(key, "token") || contains(key, "key") || contains(key, "secret") || contains(key, "webhook")) {
		return value[:4] + "****" + value[len(value)-4:]
	}
	return value
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && (s[0:len(substr)] == substr || contains(s[1:], substr)))
}
