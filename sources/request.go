package sources

import (
	"net/http"
	"net/url"
	"strings"
)

const (
	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0"
)

type Req struct {
	Schema   string
	Endpoint string
	Path     string
	Method   string
	Header   map[string]string
	Query    string
	Body     string
}

// Request makes an HTTP request
func (r *Req) Request() (*http.Request, error) {
	u := &url.URL{
		Scheme:   r.Schema,
		Host:     r.Endpoint,
		Path:     r.Path,
		RawQuery: r.Query,
	}

	request, err := http.NewRequest(r.Method, u.String(), strings.NewReader(r.Body))
	if err != nil {
		return nil, err
	}

	request.Header.Set("User-Agent", userAgent)
	for k, v := range r.Header {
		request.Header.Set(k, v)
	}

	return request, nil
}
