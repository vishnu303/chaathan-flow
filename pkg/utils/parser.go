package utils

import (
	"bufio"
	"chaathan/pkg/database"
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

// ParseSubdomainsFile reads a file with one subdomain per line and adds to database
func ParseSubdomainsFile(scanID int64, filePath, source string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	if len(domains) > 0 {
		if err := database.AddSubdomains(scanID, domains, source); err != nil {
			return 0, err
		}
	}

	return len(domains), nil
}

// HttpxResult represents a line from httpx JSON output
type HttpxResult struct {
	URL           string   `json:"url"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	ContentType   string   `json:"content_type"`
	Technologies  []string `json:"tech"`
	Host          string   `json:"host"`
	Input         string   `json:"input"`
	ResponseTime  string   `json:"response_time"`
}

// ParseHttpxOutput parses httpx JSON output and stores in database
func ParseHttpxOutput(scanID int64, filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result HttpxResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		tech := ""
		if len(result.Technologies) > 0 {
			techJSON, _ := json.Marshal(result.Technologies)
			tech = string(techJSON)
		}

		if err := database.AddURL(scanID, result.URL, result.StatusCode, result.ContentType, result.Title, tech, "httpx"); err != nil {
			continue
		}

		// Also mark subdomain as live
		host := result.Host
		if host == "" {
			host = result.Input
		}
		if host != "" {
			database.UpdateSubdomainLive(scanID, host, true, "")
		}

		count++
	}

	return count, scanner.Err()
}

// NucleiResult represents a line from nuclei JSON output
type NucleiResult struct {
	TemplateID  string `json:"template-id"`
	TemplateName string `json:"name"`
	Severity    string `json:"severity"`
	Host        string `json:"host"`
	MatchedAt   string `json:"matched-at"`
	ExtractorName string `json:"extractor-name"`
	Matcher     string `json:"matcher-name"`
	Description string `json:"description"`
	Extracted   []string `json:"extracted-results"`
}

// ParseNucleiOutput parses nuclei JSON output and stores in database
func ParseNucleiOutput(scanID int64, filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	// Increase buffer size for large lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		evidence := ""
		if len(result.Extracted) > 0 {
			evidence = strings.Join(result.Extracted, "\n")
		}

		name := result.TemplateName
		if name == "" {
			name = result.TemplateID
		}

		err := database.AddVulnerability(
			scanID,
			result.Host,
			result.MatchedAt,
			result.TemplateID,
			name,
			strings.ToLower(result.Severity),
			result.Description,
			result.Matcher,
			evidence,
		)
		if err != nil {
			continue
		}
		count++
	}

	return count, scanner.Err()
}

// NaabuResult represents a line from naabu output
type NaabuResult struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// ParseNaabuOutput parses naabu output and stores in database
func ParseNaabuOutput(scanID int64, filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Naabu outputs in format: host:port or JSON
		var host string
		var port int

		// Try JSON first
		var result NaabuResult
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			host = result.Host
			if host == "" {
				host = result.IP
			}
			port = result.Port
		} else {
			// Try host:port format
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				host = parts[0]
				port, _ = strconv.Atoi(parts[1])
			}
		}

		if host != "" && port > 0 {
			if err := database.AddPort(scanID, host, port, "tcp", ""); err != nil {
				continue
			}
			count++
		}
	}

	return count, scanner.Err()
}

// ParseEndpointsFile parses a file with endpoints (one per line)
func ParseEndpointsFile(scanID int64, filePath, source string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Determine method if present
		method := ""
		url := line

		// Some tools output "METHOD URL"
		parts := strings.Fields(line)
		if len(parts) >= 2 && isHTTPMethod(parts[0]) {
			method = parts[0]
			url = parts[1]
		}

		if err := database.AddEndpoint(scanID, url, method, source); err != nil {
			continue
		}
		count++
	}

	return count, scanner.Err()
}

// ParseURLsFile parses a file with URLs (one per line)
func ParseURLsFile(scanID int64, filePath, source string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if err := database.AddURL(scanID, line, 0, "", "", "", source); err != nil {
			continue
		}
		count++
	}

	return count, scanner.Err()
}

func isHTTPMethod(s string) bool {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	s = strings.ToUpper(s)
	for _, m := range methods {
		if s == m {
			return true
		}
	}
	return false
}
