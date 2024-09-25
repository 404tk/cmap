package plugins

import (
	"context"
	"log"

	"github.com/404tk/cmap/sources"
)

type Keyword struct {
	IP     []string
	Domain []string
	Icon   []struct {
		Md5  string
		Mmh3 string
	}
	Cert []string
}

type Plugin interface {
	Name() string
	Query(*sources.Session, interface{}) (chan sources.Result, error)
	QueryIP(context.Context, string)
	QueryDomain(context.Context, string)
	QueryIcon(context.Context, string)
	QueryCert(context.Context, string)
}

var Plugins = make(map[string]Plugin)

func registerPlugin(pName string, p Plugin) {
	if _, ok := Plugins[pName]; ok {
		log.Fatalln("插件名称重复:", pName)
	}
	Plugins[pName] = p
}
