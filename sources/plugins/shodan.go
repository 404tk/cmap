package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/404tk/cmap/options"
	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
	"github.com/dlclark/regexp2"
)

const (
	ShodanSize = 100
)

var replacePat = regexp2.MustCompile(`(\s{0,}&&\s{0,})`, regexp2.None)

type Shodan struct {
	apikey  string
	session *sources.Session
	results chan sources.Result
}

func (f Shodan) Name() string {
	return "shodan"
}

func (f Shodan) QueryAsset(ctx context.Context, session *sources.Session, query interface{}) (chan sources.Result, error) {
	apikey := config.RandomKey(f.Name())
	if apikey == nil {
		return nil, fmt.Errorf("empty %s keys", f.Name())
	}
	f.apikey = *apikey
	f.session = session
	f.results = make(chan sources.Result)

	k := query.(options.Keyword)
	go func() {
		defer close(f.results)

		for _, ip := range k.IP {
			f.queryIP(ctx, ip)
		}
		for _, domain := range k.Domain {
			f.queryDomain(ctx, domain)
		}
		for _, q := range k.Icons {
			f.queryIcon(ctx, q.Mmh3)
		}
		for _, q := range k.DSL {
			str := q.Expr
			if strings.Contains(str, "||") {
				// 暂不支持OR连接符
				continue
			}
			str, err := replacePat.Replace(str, " ", -1, -1)
			if err != nil {
				continue
			}
			for i, g := range q.Groups {
				dsl := f.parseDSL(g.Key, g.Value)
				if dsl == "" {
					goto next
				}
				str = strings.Replace(str, fmt.Sprintf("[%d]", i), dsl, 1)
			}
			f.search(ctx, str, q.Raw)
		next:
		}
	}()

	return f.results, nil
}

func (f Shodan) queryIP(ctx context.Context, ip string) {
	if len(ip) == 0 {
		return
	}
	f.search(ctx, f.parseDSL("ip", ip), ip)
}

func (f Shodan) queryDomain(ctx context.Context, domain string) {
	if len(domain) == 0 {
		return
	}
	f.search(ctx, f.parseDSL("domain", domain), domain)
}

func (f Shodan) queryIcon(ctx context.Context, hash string) {
	if len(hash) == 0 {
		return
	}
	f.search(ctx, f.parseDSL("icon.mmh3", hash), hash)
}

func (f Shodan) parseDSL(k, v string) string {
	switch k {
	case "ip":
		return fmt.Sprintf(`net:"%s"`, v)
	case "domain":
		return fmt.Sprintf(`hostname:"%s"`, v)
	case "icon.mmh3":
		return fmt.Sprintf(`http.favicon.hash:"%s"`, v)
	case "cert":
		return fmt.Sprintf(`ssl:"%s"`, v)
	case "title":
		return fmt.Sprintf(`http.title:"%s"`, v)
	case "body":
		return fmt.Sprintf(`http.html:"%s"`, v)
	default:
		return ""
	}
}

type ShodanResponse struct {
	Total int `json:"total"`
	//Results []map[string]interface{} `json:"matches"`
	Results []struct {
		IP        string   `json:"ip_str"`
		Port      int      `json:"port"`
		Transport string   `json:"transport"`
		Hostname  []string `json:"hostname"`
		Product   string   `json:"product"`
		Http      struct {
			Host  string `json:"host"`
			Title string `json:"title"`
		}
		SSL struct {
			Chain []string `json:"chain"`
		} `json:"ssl"`
		Timestamp string `json:"timestamp"`
	} `json:"matches"`
}

func (f Shodan) search(ctx context.Context, query, prompt string) {
	page := 1
	var numberOfResults int
	for {
		req := &sources.Req{
			Schema:   "https",
			Endpoint: "api.shodan.io",
			Path:     "/shodan/host/search",
			Method:   "GET",
			Header:   map[string]string{"User-Agent": "curl/8.7.1"},
		}
		req.Query = fmt.Sprintf("key=%s&query=%s&page=%d",
			f.apikey, url.QueryEscape(query), page)
		request, err := req.Request()
		if err != nil {
			f.results <- sources.Result{Source: f.Name(), Error: err}
			return
		}
		resp, err := f.session.Do(request, f.Name())
		if err != nil {
			f.results <- sources.Result{Source: f.Name(), Error: err}
			return
		}

		shodanResponse := &ShodanResponse{}
		if err := json.NewDecoder(resp.Body).Decode(shodanResponse); err != nil {
			f.results <- sources.Result{Source: f.Name(), Error: err}
			return
		}

		for _, res := range shodanResponse.Results {
			result := sources.Result{Source: f.Name(), Prompt: prompt}
			if len(res.IP) == 0 {
				continue

			}
			result.IP = res.IP
			result.Port = fmt.Sprintf("%d/%s", res.Port, res.Transport)
			if len(res.Hostname) > 0 {
				result.Host = res.Hostname
			}
			if len(res.Http.Host) > 0 {
				result.Title = res.Http.Title
				if len(res.SSL.Chain) > 0 {
					result.Protocol = "https"
					result.Url = fmt.Sprintf("https://%s", result.IpPort())
				} else {
					result.Protocol = "http"
					result.Url = fmt.Sprintf("http://%s", result.IpPort())
				}
			}
			result.Fingerprint = res.Product
			parsedTime, err := time.Parse(time.RFC3339Nano[:26], res.Timestamp)
			if err == nil {
				result.LastUpdate = parsedTime.Format(time.DateTime)
			}
			f.results <- result
		}

		numberOfResults += len(shodanResponse.Results)
		if len(shodanResponse.Results) < FofaSize || numberOfResults > shodanResponse.Total {
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
			page++
		}
	}
}

func init() {
	registerPlugin("shodan", Shodan{})
}

// QuerySubdomain 子域名收集
func (f Shodan) QuerySubdomain(ctx context.Context, session *sources.Session, domain string) ([]string, error) {
	apikey := config.RandomKey(f.Name())
	if apikey == nil {
		return nil, fmt.Errorf("empty %s keys", f.Name())
	}

	req := &sources.Req{
		Schema:   "https",
		Endpoint: "api.shodan.io",
		Path:     fmt.Sprintf("/dns/domain/%s", domain),
		Method:   "GET",
		Header:   map[string]string{"User-Agent": "curl/8.7.1"},
	}

	page := 1
	res := make(map[string]struct{})
	var lastErr error

	for {
		select {
		case <-ctx.Done():
			goto done
		default:
		}
		req.Query = fmt.Sprintf("key=%s&page=%d", *apikey, page)
		request, err := req.Request()
		if err != nil {
			lastErr = err
			break
		}
		resp, err := session.Do(request, f.Name())
		if err != nil {
			lastErr = err
			break
		}

		type shodanDNS struct {
			Domain     string   `json:"domain"`
			Subdomains []string `json:"subdomains"`
			More       bool     `json:"more"`
		}
		var dnsResp shodanDNS
		if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
			resp.Body.Close()
			lastErr = err
			break
		}
		resp.Body.Close()

		for _, sub := range dnsResp.Subdomains {
			fullSub := sub + "." + dnsResp.Domain
			if strings.HasSuffix(fullSub, "."+domain) {
				res[fullSub] = struct{}{}
			}
		}

		if !dnsResp.More {
			break
		}
		page++
	}

done:
	result := make([]string, 0, len(res))
	for k := range res {
		result = append(result, k)
	}
	return result, lastErr
}

// VerifyKeys 验证 Shodan API 密钥
func (f Shodan) VerifyKeys(session *sources.Session) []config.KeyStatus {
	keys := config.GetKeys(f.Name())
	if len(keys) == 0 {
		return nil
	}

	results := make([]config.KeyStatus, 0, len(keys))
	for i, key := range keys {
		// Shodan 限速 1 req/s
		if i > 0 {
			time.Sleep(time.Second)
		}
		status := config.KeyStatus{Key: maskKey(key)}

		req := &sources.Req{
			Schema:   "https",
			Endpoint: "api.shodan.io",
			Path:     "/api-info",
			Method:   "GET",
			Header:   map[string]string{"User-Agent": "curl/8.7.1"},
			Query:    fmt.Sprintf("key=%s", key),
		}

		request, err := req.Request()
		if err != nil {
			status.Error = err
			results = append(results, status)
			continue
		}

		resp, err := session.Do(request, f.Name())
		if err != nil {
			status.Error = err
			results = append(results, status)
			continue
		}

		type shodanAPIInfo struct {
			QueryCredits int64  `json:"query_credits"`
			ScanCredits  int64  `json:"scan_credits"`
			Plan         string `json:"plan"`
			Error        string `json:"error"`
		}
		var info shodanAPIInfo
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			resp.Body.Close()
			status.Error = err
			results = append(results, status)
			continue
		}
		resp.Body.Close()

		if info.Error != "" {
			status.Error = fmt.Errorf("%s", info.Error)
			results = append(results, status)
			continue
		}

		status.Valid = true
		status.Credits = info.QueryCredits
		status.Info = fmt.Sprintf("Plan: %s", info.Plan)
		results = append(results, status)
	}
	return results
}
