package plugins

import (
	"context"
	"log"

	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
)

// Plugin 统一插件接口
type Plugin interface {
	Name() string
	QueryAsset(context.Context, *sources.Session, interface{}) (chan sources.Result, error)
	QuerySubdomain(context.Context, *sources.Session, string) ([]string, error)
	VerifyKeys(*sources.Session) []config.KeyStatus
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

// maskKey 脱敏显示密钥
func maskKey(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[:4] + "****" + key[len(key)-4:]
}
