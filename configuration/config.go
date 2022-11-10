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
	BotD struct {
		Pro    bool   `toml:"pro"`
		Public string `toml:"public"`
		Secret string `toml:"secret"`
		Import string `toml:"import"`
		Script string
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
	Config.BotD.Script = GetScriptBotD()
}

// Setup BotD detection script
func GetScriptBotD() string {

	if Config.BotD.Import == "" {
		if Config.BotD.Pro {
			Config.BotD.Import = "https://fpcdn.io/v3/" + Config.BotD.Public
		} else {
			Config.BotD.Import = "https://openfpcdn.io/botd/v1"
		}
	}

	if Config.BotD.Pro {
		return `const fingerprint = import(` + Config.BotD.Import + `").then(
			(FingerprintJS) => FingerprintJS.load()
		  );
		  
		fingerprint
			.then((fp) => fp.get())
			.then((result) => {
			  data.requestid = result.requestId;
			  data.isbot = false;
			});`
	}

	return `const fingerprint = import('` + Config.BotD.Import + `').then((Botd) => Botd.load())

    fingerprint
      .then((botd) => botd.detect())
      .then((result) => data.isbot = result.bot);`
}
