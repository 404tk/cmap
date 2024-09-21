package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
)

const (
	ShodanSize = 100
)

type Shodan struct {
	apikey  string
	session *sources.Session
	results chan sources.Result
}

func (f Shodan) Name() string {
	return "shodan"
}

func (f Shodan) Query(session *sources.Session, query interface{}) (chan sources.Result, error) {
	apikey := config.RandomKey(f.Name())
	if apikey == nil {
		return nil, fmt.Errorf("empty %s keys", f.Name())
	}
	f.apikey = apikey.(string)
	f.session = session
	f.results = make(chan sources.Result)

	// 查询总时长限制10分钟
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	q := query.(Keyword)
	go func() {
		defer close(f.results)

		f.QueryIP(ctx, q.IP)
		f.QueryDomain(ctx, q.Domain)
		f.QueryIcon(ctx, q.Icon.Mmh3)
		f.QueryCert(ctx, q.Cert)
	}()

	return f.results, nil
}

func (f Shodan) QueryIP(ctx context.Context, ip string) {
	if len(ip) == 0 {
		return
	}
	query := fmt.Sprintf(`net:"%s"`, ip)
	f.search(ctx, query)
}

func (f Shodan) QueryDomain(ctx context.Context, domain string) {
	if len(domain) == 0 {
		return
	}
	query := fmt.Sprintf(`hostname:"%s"`, domain)
	f.search(ctx, query)
}

func (f Shodan) QueryIcon(ctx context.Context, hash string) {
	if len(hash) == 0 {
		return
	}
	query := fmt.Sprintf(`http.favicon.hash:"%s"`, hash)
	f.search(ctx, query)
}

func (f Shodan) QueryCert(ctx context.Context, keyword string) {
	if len(keyword) == 0 {
		return
	}
	query := fmt.Sprintf(`ssl:"%s"`, keyword)
	f.search(ctx, query)
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

func (f Shodan) search(ctx context.Context, query string) {
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
			result := sources.Result{Source: f.Name()}
			if len(res.IP) == 0 {
				continue

			}
			result.IP = res.IP
			result.Port = fmt.Sprintf("%d/%s", res.Port, res.Transport)
			for _, hostname := range res.Hostname {
				result.Host = append(result.Host, hostname)
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
				result.LastUpdate = parsedTime.Format("2006-01-02 15:04:05")
			}
			result.Prompt = query
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
