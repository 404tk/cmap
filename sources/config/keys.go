package config

import (
	"math/rand"
)

var apikeys = make(map[string]interface{})

type FofaAuth struct {
	Email string
	Key   string
}

func RandomKey(name string) interface{} {
	v, ok := apikeys[name]
	if !ok {
		return nil
	}

	if name == "fofa" {
		auths := v.([]FofaAuth)
		if len(auths) < 1 {
			return nil
		}
		return auths[rand.Intn(len(auths))]
	} else {
		keys := v.([]string)
		if len(keys) < 1 {
			return nil
		}
		return keys[rand.Intn(len(keys))]
	}
}
