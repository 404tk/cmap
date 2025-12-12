package plugins

import (
	"context"
	"log"

	"github.com/404tk/cmap/sources"
)

// Plugin 统一插件接口
type Plugin interface {
	Name() string
	QueryAsset(context.Context, *sources.Session, interface{}) (chan sources.Result, error)
	QuerySubdomain(context.Context, *sources.Session, string) ([]string, error)
}

var Plugins = make(map[string]Plugin)

func registerPlugin(pName string, p Plugin) {
	if _, ok := Plugins[pName]; ok {
		log.Fatalln("插件名称重复:", pName)
	}
	Plugins[pName] = p
}

func truncateString(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
