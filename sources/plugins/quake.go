package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
)

const (
	QuakeSize = 500
)

type Quake struct {
	apikey  string
	session *sources.Session
	results chan sources.Result
}

func (f Quake) Name() string {
	return "quake"
}

func (f Quake) Query(session *sources.Session, query interface{}) (chan sources.Result, error) {
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

func (f Quake) QueryIP(ctx context.Context, ip string) {
	if len(ip) == 0 {
		return
	}
	query := fmt.Sprintf(`ip:"%s"`, ip)
	f.search(ctx, query)
}

func (f Quake) QueryDomain(ctx context.Context, domain string) {
	if len(domain) == 0 {
		return
	}
	query := fmt.Sprintf(`domain:"*.%s"`, domain)
	f.search(ctx, query)
}

func (f Quake) QueryIcon(ctx context.Context, hash string) {
	if len(hash) == 0 {
		return
	}
	query := fmt.Sprintf(`favicon:"%s"`, hash)
	f.search(ctx, query)
}

func (f Quake) QueryCert(ctx context.Context, keyword string) {
	if len(keyword) == 0 {
		return
	}
	query := fmt.Sprintf(`cert:"%s"`, keyword)
	f.search(ctx, query)
}

type QuakeRequest struct {
	Query       string   `json:"query"`
	Size        int      `json:"size"`
	Start       int      `json:"start"`
	IgnoreCache bool     `json:"ignore_cache"`
	Include     []string `json:"include"`
}

func (req *QuakeRequest) toString() string {
	jsonStr, err := json.Marshal(req)
	if err != nil {
		return "{}"
	}
	return string(jsonStr)
}

func (f Quake) search(ctx context.Context, query string) {
	numberOfResults := 0
	for {
		quakeRequest := &QuakeRequest{
			Query:       query,
			Size:        QuakeSize,
			Start:       numberOfResults,
			IgnoreCache: true,
			Include:     []string{"ip", "port", "hostname", "transport", "service.name", "service.http.host", "service.http.title"},
		}
		req := &sources.Req{
			Schema:   "https",
			Endpoint: "quake.360.net",
			Path:     "/api/v3/search/quake_service",
			Method:   "POST",
			Header: map[string]string{
				"Content-Type": "application/json",
				"X-QuakeToken": f.apikey,
			},
			Body: quakeRequest.toString(),
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

		response := &QuakeResponse{}
		if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
			f.results <- sources.Result{Source: f.Name(), Error: err}
			return
		}
		if c, _ := json.Marshal(response.Code); string(c) != "0" {
			f.results <- sources.Result{Source: f.Name(), Error: fmt.Errorf(response.Message)}
			return
		}

		type quakeData struct {
			Hostname  string `json:"hostname"`
			IP        string `json:"ip"`
			Port      int    `json:"port"`
			Transport string `json:"transport"`
			Service   struct {
				Name string `json:"name"`
				Http struct {
					Host  string `json:"host"`
					Title string `json:"title"`
				} `json:"http"`
			} `json:"service"`
		}
		d, _ := json.Marshal(response.Data)
		var data []quakeData
		if err := json.Unmarshal(d, &data); err != nil {
			f.results <- sources.Result{Source: f.Name(), Error: fmt.Errorf("wrong format")}
			return
		}

		for _, res := range data {
			result := sources.Result{Source: f.Name()}
			result.IP = res.IP
			result.Port = fmt.Sprintf("%d/%s", res.Port, res.Transport)
			result.Protocol = res.Service.Name
			result.Title = res.Service.Http.Title
			if len(res.Service.Http.Host) > 0 && !strings.Contains(res.Service.Http.Host, res.IP) {
				host := strings.Split(res.Service.Http.Host, ":")[0]
				result.Host = append(result.Host, host)
			}
			if result.Protocol == "http" {
				result.Url = fmt.Sprintf("http://%s", res.Service.Http.Host)
			} else if result.Protocol == "http/ssl" {
				result.Url = fmt.Sprintf("https://%s", res.Service.Http.Host)
			}
			result.Prompt = query

			f.results <- result
		}

		if response.Meta.Pagination.Count < QuakeSize {
			return
		}

		numberOfResults += len(data)
		if response.Meta.Pagination.Count > 0 && numberOfResults >= response.Meta.Pagination.Total {
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
			continue
		}
	}
}

type QuakeResponse struct {
	Code    interface{} `json:"code"`
	Data    interface{} `json:"data"`
	Message string      `json:"message"`
	Meta    struct {
		Pagination struct {
			Count     int `json:"count"`
			PageIndex int `json:"page_index"`
			PageSize  int `json:"page_size"`
			Total     int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
}

func init() {
	registerPlugin("quake", Quake{})
}
