package configuration

import (
	"github.com/BurntSushi/toml"
)

// Configuration information set up using config.toml
type Configuration struct {
	Listen string `toml:"listen"`
	Tls    struct {
		Cert string `toml:"cert"`
		Key  string `toml:"key"`
	}
	Redirect struct {
		Good string `toml:"good"`
		Bad  string `toml:"bad"`
	}
	Captcha struct {
		Version    int    `toml:"version"`
		SiteKey    string `toml:"site"`
		PrivateKey string `toml:"private"`
	}
	Match struct {
		Route      string   `toml:"route"`
		Parameters []string `toml:"parameters"`
	}
}

var Config Configuration

// Retrieve configuration from file
func Parse(configFile string) {
	_, err := toml.DecodeFile(configFile, &Config)
	if err != nil {
		panic(err)
	}
}
