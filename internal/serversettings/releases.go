package serversettings

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

var releaseClient = &http.Client{Timeout: 10 * time.Second}

// fetchRelease returns the newest release (stable: the latest non-prerelease;
// beta: the newest of all), or nil when none exists.
func fetchRelease(ctx context.Context, channel string) (*release, error) {
	url := "https://api.github.com/repos/" + Repo + "/releases/latest"
	if channel == "beta" {
		url = "https://api.github.com/repos/" + Repo + "/releases?per_page=1"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "xcp-panel")
	resp, err := releaseClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach GitHub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if channel == "beta" {
		var list []release
		if err := json.Unmarshal(body, &list); err != nil || len(list) == 0 {
			return nil, err
		}
		return &list[0], nil
	}
	var rel release
	if err := json.Unmarshal(body, &rel); err != nil || rel.Tag == "" {
		return nil, err
	}
	return &rel, nil
}
