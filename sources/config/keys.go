package config

import (
	"math/rand"
)

const (
	PlatformFofa       = "fofa"
	PlatformHunter     = "hunter"
	PlatformQuake      = "quake"
	PlatformShodan     = "shodan"
	PlatformZoomeye    = "zoomeye"
	PlatformVirusTotal = "virustotal"
	PlatformAlienVault = "alienvault"
)

var apikeys = make(map[string]interface{})

// SetKeys 设置 API 密钥
func SetKeys(platform string, keys []string) {
	apikeys[platform] = keys
}

// GetKeys 获取指定平台的所有密钥
func GetKeys(platform string) []string {
	v, ok := apikeys[platform]
	if !ok {
		return nil
	}
	return v.([]string)
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

// KeyStatus 凭据验证结果
type KeyStatus struct {
	Key     string // 密钥（脱敏显示）
	Valid   bool   // 是否有效
	Credits int64  // 剩余额度（若平台支持）
	Info    string // 附加信息
	Error   error  // 错误信息
}
