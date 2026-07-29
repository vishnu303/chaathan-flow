package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vishnu303/chaathan/pkg/logger"
)

// githubRepo defines the canonical GitHub repository path for Chaathan
const githubRepo = "vishnu303/chaathan"

var apiBaseURL = "https://api.github.com"

// ReleaseInfo holds details about the latest available release.
type ReleaseInfo struct {
	LatestVersion string
	URL           string
	IsNewer       bool
}

// CheckForUpdates queries the GitHub Releases API to see if a newer version is available.
//
// Gap Notice: This function is check-only. It performs version check only
// and does NOT download, apply, or roll back releases. The self-update apply logic is
// deferred as a known gap until a security-reviewed installation path is provided.
func CheckForUpdates(currentVersion string) (*ReleaseInfo, error) {
	// Set connection timeout to 10s
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	url := fmt.Sprintf("%s/repos/%s/releases/latest", apiBaseURL, githubRepo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	// Set User-Agent containing the current version
	req.Header.Set("User-Agent", fmt.Sprintf("chaathan-updater/%s", currentVersion))

	var resp *http.Response
	// Retry once on rate limits or server errors with a backoff
	for attempt := 0; attempt < 2; attempt++ {
		resp, err = client.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode <= 599) {
				if attempt == 0 {
					resp.Body.Close()
					time.Sleep(2 * time.Second)
					continue
				}
			}
			break
		}
		if attempt == 0 {
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Log if rate limit is near exhaustion
	if remainingHeader := resp.Header.Get("X-RateLimit-Remaining"); remainingHeader != "" {
		if remaining, err := strconv.Atoi(remainingHeader); err == nil && remaining <= 3 {
			logger.FileDebug("update: GitHub API rate limit near zero: %d remaining", remaining)
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status: %s", resp.Status)
	}

	var ghRelease struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghRelease); err != nil {
		return nil, err
	}

	info := &ReleaseInfo{
		LatestVersion: ghRelease.TagName,
		URL:           ghRelease.HTMLURL,
		IsNewer:       IsNewer(currentVersion, ghRelease.TagName),
	}

	return info, nil
}

// IsNewer compares the current version against the latest fetched version using SemVer rules.
//
// If the current version is "dev", empty "", or has a "dev-" prefix, this function
// returns false early to prevent update prompts on development builds.
func IsNewer(current, latest string) bool {
	if current == "dev" || current == "" || strings.HasPrefix(current, "dev-") {
		return false
	}

	currClean := cleanVersion(current)
	lateClean := cleanVersion(latest)

	currParts := strings.SplitN(currClean, "-", 2)
	lateParts := strings.SplitN(lateClean, "-", 2)

	currVer := currParts[0]
	lateVer := lateParts[0]

	currNums, errCurr := parseVersionNumbers(currVer)
	lateNums, errLate := parseVersionNumbers(lateVer)

	// Fall back to lexicographical string comparison if segment parsing fails
	if errCurr != nil || errLate != nil {
		return lateVer > currVer
	}

	// Compare major, minor, and patch numbers
	for i := 0; i < 3; i++ {
		if lateNums[i] > currNums[i] {
			return true
		}
		if lateNums[i] < currNums[i] {
			return false
		}
	}

	// Handle pre-releases (e.g. v1.0.0-beta.1)
	// Under SemVer: stable release > pre-release (e.g. v1.0.0 > v1.0.0-beta.1)
	hasCurrPre := len(currParts) > 1
	hasLatePre := len(lateParts) > 1

	if hasCurrPre && !hasLatePre {
		// Current is pre-release, latest is stable: latest is newer
		return true
	}
	if !hasCurrPre && hasLatePre {
		// Current is stable, latest is pre-release: current is newer
		return false
	}
	if hasCurrPre && hasLatePre {
		// Segment-by-segment comparison of numeric and lexicographical pre-release tags
		return comparePreRelease(lateParts[1], currParts[1])
	}

	return false
}

func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	return v
}

// parseVersionNumbers detects dropped components/4-part versions and returns an error
func parseVersionNumbers(v string) ([3]int, error) {
	parts := strings.Split(v, ".")
	var nums [3]int
	if len(parts) > 3 {
		return nums, fmt.Errorf("more than 3 components in version: %s", v)
	}
	for i := 0; i < 3; i++ {
		if i < len(parts) {
			n, err := strconv.Atoi(parts[i])
			if err != nil {
				return nums, fmt.Errorf("non-numeric component %q in version %q: %w", parts[i], v, err)
			}
			nums[i] = n
		}
	}
	return nums, nil
}

// comparePreRelease compares pre-release suffixes
func comparePreRelease(late, curr string) bool {
	lateSegs := strings.Split(late, ".")
	currSegs := strings.Split(curr, ".")

	minLen := len(lateSegs)
	if len(currSegs) < minLen {
		minLen = len(currSegs)
	}

	for i := 0; i < minLen; i++ {
		lSeg := lateSegs[i]
		cSeg := currSegs[i]

		if lSeg == cSeg {
			continue
		}

		lNum, errL := strconv.Atoi(lSeg)
		cNum, errC := strconv.Atoi(cSeg)

		if errL == nil && errC == nil {
			if lNum != cNum {
				return lNum > cNum
			}
		} else {
			if lSeg != cSeg {
				return lSeg > cSeg
			}
		}
	}

	return len(lateSegs) > len(currSegs)
}
