package plugins

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
)

const (
	HunterSize = 100
)

type Hunter struct {
	apikey  string
	session *sources.Session
	results chan sources.Result
}

func (f Hunter) Name() string {
	return "hunter"
}

func (f Hunter) Query(session *sources.Session, query interface{}) (chan sources.Result, error) {
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
		f.QueryIcon(ctx, q.Icon.Md5)
		f.QueryCert(ctx, q.Cert)
	}()

	return f.results, nil
}

func (f Hunter) QueryIP(ctx context.Context, ip string) {
	if len(ip) == 0 {
		return
	}
	query := fmt.Sprintf(`ip="%s"`, ip)
	f.search(ctx, query)
}

func (f Hunter) QueryDomain(ctx context.Context, domain string) {
	if len(domain) == 0 {
		return
	}
	query := fmt.Sprintf(`domain.suffix="%s"`, domain)
	f.search(ctx, query)
}

func (f Hunter) QueryIcon(ctx context.Context, hash string) {
	if len(hash) == 0 {
		return
	}
	query := fmt.Sprintf(`web.icon="%s"`, hash)
	f.search(ctx, query)
}

func (f Hunter) QueryCert(ctx context.Context, keyword string) {
	if len(keyword) == 0 {
		return
	}
	query := fmt.Sprintf(`cert="%s"`, keyword)
	f.search(ctx, query)
}

type HunterResponse struct {
	Code int `json:"code"`
	Data struct {
		AccountType string `json:"account_type"`
		Total       int    `json:"total"`
		Time        int    `json:"time"`
		Arr         []struct {
			IP           string `json:"ip"`
			Port         int    `json:"port"`
			Domain       string `json:"domain"`
			BaseProtocol string `json:"base_protocol"`
			Protocol     string `json:"protocol"`
			UpdatedAt    string `json:"updated_at"`
			Url          string `json:"url"`
			WebTitle     string `json:"web_title"`
		} `json:"arr"`
		ConsumeQuota string `json:"consume_quota"`
		RestQuota    string `json:"rest_quota"`
	} `json:"data"`
	Msg string `json:"message"`
}

func (f Hunter) search(ctx context.Context, query string) {
	page := 1
	for {
		base64Query := base64.URLEncoding.EncodeToString([]byte(query))
		req := &sources.Req{
			Schema:   "https",
			Endpoint: "hunter.qianxin.com",
			Path:     "/openApi/search",
			Method:   "GET",
			Header:   map[string]string{"Accept": "application/json"},
			Query: fmt.Sprintf("api-key=%s&search=%s&page=%d&page_size=%d",
				f.apikey, base64Query, page, HunterSize),
		}

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

		hunterResponse := &HunterResponse{}
		if err := json.NewDecoder(resp.Body).Decode(hunterResponse); err != nil {
			f.results <- sources.Result{Source: f.Name(), Error: err}
			return
		}
		if hunterResponse.Code != 200 {
			f.results <- sources.Result{Source: f.Name(), Error: fmt.Errorf(hunterResponse.Msg)}
			return
		}

		for _, res := range hunterResponse.Data.Arr {
			result := sources.Result{Source: f.Name()}
			result.IP = res.IP
			result.Port = fmt.Sprintf("%d/%s", res.Port, res.BaseProtocol)
			result.Protocol = res.Protocol
			result.Host = append(result.Host, res.Domain)
			result.Url = res.Url
			result.Title = res.WebTitle
			parsedTime, err := time.Parse(time.DateOnly, res.UpdatedAt)
			if err == nil {
				result.LastUpdate = parsedTime.Format("2006-01-02 15:04:05")
			}
			result.Prompt = query
			f.results <- result
		}

		if len(hunterResponse.Data.Arr) < HunterSize || hunterResponse.Data.Total == 0 {
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
	registerPlugin("hunter", Hunter{})
}
