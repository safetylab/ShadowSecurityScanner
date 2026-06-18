package epsskev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// EPSSScore is the EPSS data for a single CVE.
type EPSSScore struct {
	CVE        string
	EPSS       float64 // probability in [0,1]
	Percentile float64 // percentile in [0,1]
	Date       string  // model date (YYYY-MM-DD)
}

// epssResponse mirrors the FIRST.org EPSS API JSON shape. Numeric fields are
// returned as strings by the API, so they are decoded as strings and parsed.
type epssResponse struct {
	Status string `json:"status"`
	Data   []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

// FetchEPSS returns EPSS scores for the given CVEs, keyed by upper-cased CVE ID.
// CVEs with no EPSS data are simply absent from the map. Requests are batched.
func (c *Client) FetchEPSS(ctx context.Context, cves []string) (map[string]EPSSScore, error) {
	out := make(map[string]EPSSScore, len(cves))
	if len(cves) == 0 {
		return out, nil
	}
	for _, batch := range chunk(cves, epssBatchSize) {
		if err := c.fetchEPSSBatch(ctx, batch, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (c *Client) fetchEPSSBatch(ctx context.Context, cves []string, out map[string]EPSSScore) error {
	q := url.Values{}
	q.Set("cve", strings.Join(cves, ","))
	reqURL := c.EPSSBaseURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("epss request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("epss API: unexpected status %d", resp.StatusCode)
	}

	var body epssResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("epss decode: %w", err)
	}
	for _, d := range body.Data {
		score := EPSSScore{CVE: normaliseCVE(d.CVE), Date: d.Date}
		score.EPSS, _ = strconv.ParseFloat(d.EPSS, 64)
		score.Percentile, _ = strconv.ParseFloat(d.Percentile, 64)
		out[score.CVE] = score
	}
	return nil
}

// chunk splits s into slices of at most size elements.
func chunk(s []string, size int) [][]string {
	if size <= 0 {
		return [][]string{s}
	}
	var out [][]string
	for i := 0; i < len(s); i += size {
		end := i + size
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}
