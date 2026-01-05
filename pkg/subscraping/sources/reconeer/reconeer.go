package reconeer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Subdomains []subdomain `json:"subdomains"`
}

type subdomain struct {
	Subdomain string `json:"subdomain"`
}

type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
			return
		}
		headers := map[string]string{
			"Accept":    "application/json",
			"X-API-KEY": randomApiKey,
		}
		apiURL := fmt.Sprintf("https://www.reconeer.com/api/domain/%s", domain)
		resp, err := session.Get(ctx, apiURL, "", headers)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		defer session.DiscardHTTPResponse(resp)

		if resp.StatusCode != 200 {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("request failed with status %d", resp.StatusCode)}
			s.errors++
			return
		}
		var responseData response
		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(&responseData)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}
		for _, result := range responseData.Subdomains {
			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: result.Subdomain}:
				s.results++
			}
		}
	}()
	return results
}

func (s *Source) Name() string {
	return "reconeer"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
