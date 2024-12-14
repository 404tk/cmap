package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/404tk/cmap/options"
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
			f.queryIcon(ctx, q.Md5)
		}
		for _, q := range k.DSL {
			str := q.Expr
			str = strings.ReplaceAll(str, "&&", "AND")
			str = strings.ReplaceAll(str, "||", "OR")
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

func (f Quake) queryIP(ctx context.Context, ip string) {
	if len(ip) == 0 {
		return
	}
	f.search(ctx, f.parseDSL("ip", ip), ip)
}

func (f Quake) queryDomain(ctx context.Context, domain string) {
	if len(domain) == 0 {
		return
	}
	f.search(ctx, f.parseDSL("domain", domain), domain)
}

func (f Quake) queryIcon(ctx context.Context, hash string) {
	if len(hash) == 0 {
		return
	}
	f.search(ctx, f.parseDSL("icon.md5", hash), hash)
}

func (f Quake) parseDSL(k, v string) string {
	switch k {
	case "ip":
		return fmt.Sprintf(`ip:"%s"`, v)
	case "domain":
		return fmt.Sprintf(`domain:"*.%s"`, v)
	case "icon.md5":
		return fmt.Sprintf(`favicon:"%s"`, v)
	case "cert":
		return fmt.Sprintf(`cert:"%s"`, v)
	case "title":
		return fmt.Sprintf(`title:"%s"`, v)
	case "body":
		return fmt.Sprintf(`body:"%s"`, v)
	default:
		return ""
	}
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

func (f Quake) search(ctx context.Context, query, prompt string) {
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
				result.Url = fmt.Sprintf("http://%s", result.IpPort())
			} else if result.Protocol == "http/ssl" {
				result.Url = fmt.Sprintf("https://%s", result.IpPort())
			}
			result.Prompt = prompt

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
