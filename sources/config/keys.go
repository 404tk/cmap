package config

import (
	"math/rand"
)

const (
	PlatformFofa   = "fofa"
	PlatformHunter = "hunter"
	PlatformQuake  = "quake"
	PlatformShodan = "shodan"
)

var apikeys = make(map[string]interface{})

// SetKeys 设置 API 密钥
func SetKeys(platform string, keys []string) {
	apikeys[platform] = keys
}

// RandomKey 随机返回一个 API 密钥
func RandomKey(name string) *string {
	v, ok := apikeys[name]
	if !ok {
		return nil
	}

	keys := v.([]string)
	if len(keys) < 1 {
		return nil
	}

	return &keys[rand.Intn(len(keys))]
}
