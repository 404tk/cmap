package main

import (
	"log"
	"os"

	"github.com/404tk/cmap/sources/config"
	"github.com/spf13/viper"
)

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

func loadConfig(filename string) {
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
	config.SetKeys(config.PlatformFofa, viper.GetStringSlice("auth.fofa"))
	config.SetKeys(config.PlatformHunter, viper.GetStringSlice("auth.hunter"))
	config.SetKeys(config.PlatformQuake, viper.GetStringSlice("auth.quake"))
	config.SetKeys(config.PlatformShodan, viper.GetStringSlice("auth.shodan"))
}
