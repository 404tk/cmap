package plugins

import (
	"log"

	"github.com/404tk/cmap/sources"
)

type Plugin interface {
	Name() string
	Query(*sources.Session, interface{}) (chan sources.Result, error)
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
