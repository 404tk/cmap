package config

import (
	"log"
	"os"
	"strings"

	"github.com/spf13/viper"
)

func InitConfig(filename string) {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) || err != nil {
		err = os.WriteFile(filename, []byte(defaultConfigFile), os.ModePerm)
		if err != nil {
			log.Fatalf("生成配置文件失败: %v\n", err)
		}
	}
	viper.AddConfigPath(".")
	viper.SetConfigFile(filename)
	err = viper.ReadInConfig()
	if err != nil {
		log.Fatalf("读取配置文件失败: %v\n", err)
	}
	var fofa_keys []FofaAuth
	for _, i := range viper.GetStringSlice("auth.fofa") {
		item := strings.Split(i, ":")
		if len(item) > 1 {
			fofa_keys = append(fofa_keys, FofaAuth{
				Email: item[0],
				Key:   item[1],
			})
		}
	}
	apikeys["fofa"] = fofa_keys
	apikeys["hunter"] = viper.GetStringSlice("auth.hunter")
	apikeys["quake"] = viper.GetStringSlice("auth.quake")
	apikeys["shodan"] = viper.GetStringSlice("auth.shodan")
}

const defaultConfigFile = `auth:
fofa:
  # - example@gmail.com:8ccxxcccxxxccxxxxcccccxxxccccddd
hunter:
  # - 8ccxxcccxxxccxxxxcccccxxxccccddd9ccxxcccxxxccxxxxcccccxxxccccddd
quake:
  # - 12345678-abcd-efgh-ijkl-123456789012
shodan:
  # - 8ccxxcDExxxccxxxxcccFGxxxccccddd
`
