package sources

import (
	"encoding/json"
	"net"
	"strings"
)

type Result struct {
	IP          string   `json:"ip"`
	Port        string   `json:"port"`
	Protocol    string   `json:"protocol"`
	Host        []string `json:"host"`
	Url         string   `json:"url"`
	Title       string   `json:"title"`
	Fingerprint string   `json:"fingerprint"`
	Source      string   `json:"source"`
	Prompt      string   `json:"prompt"`
	LastUpdate  string   `json:"lastupdate"`
	Timestamp   int64    `json:"timestamp"`
	Error       error    `json:"-"`
}

func (r *Result) IpPort() string {
	return net.JoinHostPort(r.IP, strings.Split(r.Port, "/")[0])
}

func (r *Result) PrettyPrint() string {
	msg := r.IpPort() + "\t" + r.Protocol
	if len(r.Fingerprint) > 0 {
		msg += "\t" + r.Fingerprint
	}
	return msg
}

func (r *Result) JSON() string {
	data, _ := json.Marshal(r)
	return string(data)
}
