package updater

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	apiURL   = "https://api.github.com/repos/kohanmathers/kmresolv/releases/latest"
	cacheTTL = time.Hour
)

type Result struct {
	Available bool
	Version   string
	URL       string
}

var (
	mu       sync.Mutex
	cached   *Result
	cachedAt time.Time
)

func Check(currentVersion string) (Result, error) {
	mu.Lock()
	if cached != nil && time.Since(cachedAt) < cacheTTL {
		r := *cached
		mu.Unlock()
		return r, nil
	}
	mu.Unlock()

	tagName, htmlURL, err := fetchLatest()
	if err != nil {
		return Result{}, err
	}

	r := Result{
		Available: isNewer(tagName, currentVersion),
		Version:   strings.TrimPrefix(tagName, "v"),
		URL:       htmlURL,
	}

	mu.Lock()
	cached = &r
	cachedAt = time.Now()
	mu.Unlock()

	return r, nil
}

func fetchLatest() (tagName, htmlURL string, err error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("github API: status %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", "", fmt.Errorf("github API: decode: %w", err)
	}
	if release.TagName == "" {
		return "", "", fmt.Errorf("github API: empty tag_name")
	}
	return release.TagName, release.HTMLURL, nil
}

func isNewer(latest, current string) bool {
	lv := parseSemver(strings.TrimPrefix(latest, "v"))
	cv := parseSemver(strings.TrimPrefix(current, "v"))
	n := len(lv)
	if len(cv) > n {
		n = len(cv)
	}
	for i := 0; i < n; i++ {
		l, c := 0, 0
		if i < len(lv) {
			l = lv[i]
		}
		if i < len(cv) {
			c = cv[i]
		}
		if l > c {
			return true
		}
		if l < c {
			return false
		}
	}
	return false
}

func parseSemver(v string) []int {
	parts := strings.Split(v, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}
