package epsskev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// KEVEntry is a single entry from the CISA Known Exploited Vulnerabilities catalog.
type KEVEntry struct {
	CVE               string
	VendorProject     string
	Product           string
	VulnerabilityName string
	DateAdded         string // YYYY-MM-DD
	DueDate           string
	RequiredAction    string
}

// kevFeed mirrors the CISA KEV JSON feed.
type kevFeed struct {
	Title           string `json:"title"`
	CatalogVersion  string `json:"catalogVersion"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		CveID             string `json:"cveID"`
		VendorProject     string `json:"vendorProject"`
		Product           string `json:"product"`
		VulnerabilityName string `json:"vulnerabilityName"`
		DateAdded         string `json:"dateAdded"`
		DueDate           string `json:"dueDate"`
		RequiredAction    string `json:"requiredAction"`
	} `json:"vulnerabilities"`
}

// FetchKEV downloads the CISA KEV catalog and returns it keyed by upper-cased
// CVE ID.
func (c *Client) FetchKEV(ctx context.Context) (map[string]KEVEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.KEVURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kev request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev feed: unexpected status %d", resp.StatusCode)
	}

	var feed kevFeed
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, fmt.Errorf("kev decode: %w", err)
	}

	out := make(map[string]KEVEntry, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		cve := normaliseCVE(v.CveID)
		out[cve] = KEVEntry{
			CVE:               cve,
			VendorProject:     v.VendorProject,
			Product:           v.Product,
			VulnerabilityName: v.VulnerabilityName,
			DateAdded:         v.DateAdded,
			DueDate:           v.DueDate,
			RequiredAction:    v.RequiredAction,
		}
	}
	return out, nil
}
