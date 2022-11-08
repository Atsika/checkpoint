# Checkpoint

<div align="center">
    <img src="images/checkpoint-logo.png" width="80%">
</div>

Prevent bots from accessing your website

[![made-with-Go](https://img.shields.io/badge/Made%20with-Go-blue.svg)](http://golang.org)  [![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-license.org/)

## Introduction

Halt ! ✋  
Checkpoint is a web access control tool.  
You must prove you're human to continue.  


## Features

* Custom page
* Flexible
* reCAPTCHA
* BotD
* Secure TLS configuration
* Simple configuration
* Cross-platform

### 👀 Custom page

Checkpoint allows you to display custom HTML pages before detecting if the request comes from a bot or not. Provided page mimics Google's "unsual traffic" page. It's a pretty simple page yet really effective because it should sound familiar to anyone. This is very valuable from a social engineering point of view.

<div align="center">
    <img src="images/unusual_traffic.png">
</div>


### Flexible

Checkpoint uses Gorillax's mux middlewares to allow user flexibility. This way, anyone can plug his own code easily. To do so, you'll need to create a .go file in the `middlewares` folder. This file will be in `package middlewares`. Once you have built your middleware, simply add your main function in **Funcs** slice in [`middlewares.go`](/middlewares/middlewares.go#L8). If needed, you can also add functions in [**init**](/middlewares/middlewares.go#L11) that will be executed when Checkpoint starts. As an example, I've made a middleware that adds HSTS headers to every response.

```go
func hstsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}
```

Then added the function in the slice.

```go
Funcs = []mux.MiddlewareFunc{hstsMiddleware}
```


### 🤖 reCAPTCHA

Checkpoint relies on Google's CAPTCHA solution.

> reCAPTCHA v3 returns a score for each request without user friction. The score is based on interactions with your site and enables you to take an appropriate action for your site. - [Google's doc](https://developers.google.com/recaptcha/docs/v3)

> display and customize the reCAPTCHA v2 widget on your webpage. - [Google's doc](https://developers.google.com/recaptcha/docs/display)

Both v2 and v3 can be used. Checkpoint is provided with 2 lightweight templates, one for each version.  

**It is important to name the templates `captcha2.html` and `captcha3.html` and place them in the `static` folder**. Depending one the version specified in the configuration file, Checkpoint will get the right file.

### 🔍 BotD

Checkpoint uses BotD, a JavaScript agent capable of detecting bots. BotD is open source and be found [here](https://github.com/fingerprintjs/BotD). The pro version brings advanced bots detection.

> BotD is a bot detection platform that helps you to detect automated usage of your website. - [Fingerprint's doc](https://dev.fingerprint.com/docs/bot-detection-quick-start-guide)


### 🔒 Secure TLS configuration

Checkpoint's TLS configuration follows the state-of-the art cryptography. It uses TLS 1.3 exclusivly with secure cipher suites :
* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
* TLS_RSA_WITH_AES_256_GCM_SHA384
* TLS_RSA_WITH_AES_256_CBC_SHA


### 📄 Simple configuration

Checkpoint is easily configurable through a [config file](example.config.toml). You will need to generate a TLS certificate using [Let's Encrypt](https://letsencrypt.org/) for example or a self-signed certificate using [mkcert](https://github.com/FiloSottile/mkcert).  

The different values to configure are the following :
* listen : Address on which to listen (format: IP:PORT)
* tls :
  * cert : Path to TLS certificate
  * key : Path to TLS certificate private key
* captcha :
  * version : reCAPTCHA version to be used (only options are 2 or 3)
  * site : reCAPATCHA site key
  * private : reCAPTCHA private key
* botd :
  * pro : Use or not BotD's pro version (only options are true or false)
  * public : BotD Pro public API key
  * secret : BotD Pro secret API key
* redirect : 
  * good : URL to redirect to when CAPTCHA is solved (where human go)
  * bad : URL to redirect to when CAPTCH has failed (where bot go)
* match :
  * route : Route that will trigger a CAPTCHA challenge. Any other route will redirect the user to the "bad URL".
  * parameters : Required parameters in initial request. If those parameters are missing, the user will always be redirected to the "bad URL".

> To start using reCAPTCHA, you need to [sign up for an API key pair](http://www.google.com/recaptcha/admin) for your site. The key pair consists of a site key and secret key. The site key is used to invoke reCAPTCHA service on your site or mobile application. - [Google's doc](https://developers.google.com/recaptcha/intro#recaptcha-overview)

<details open>
    <summary>Here is an exemple of configuration file ⬇️</summary>

```toml
# URL to listen on
# Format: IP:PORT
listen = "0.0.0.0:443"

# Path to TLS cert
[tls]
cert = "/path/to/tls.crt"
key = "/path/to/tls.key"

# Google's reCAPTCHA configuration. Version can either be 2 or 3. 
# More info: https://developers.google.com/recaptcha/intro#recaptcha-overview
[captcha]
version = 3
site= "XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
private = "YYYYYYYYYYYYYYYYYYYYYYYYYYY"

# FingerprintJS BotD configuration. If you set pro to true, you will need API keys, otherwise the open-souce version will be used.
[botd]
pro = false
public = "XXXXXXXXXXXXXXXXXXXX"
secret = "YYYYYYYYYYYYYYYYYYYY"

# Redirection URLs
[redirect]
good = "https://domain.com/search/items?version=2"
bad = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

# Request need to match the following elements to be redirected to the good URL.
# Format: ["param1", "value1", "param2", "value2"]
# If you only care about the param, leave value empty: 
# ["param1", "", "param2", ""]
[match]
route = "/the/only/allowed/route"
parameters = ["uid", "", "page", "3"]

# Example of a valid URL given the above configuration: https://domain.com/the/only/allowed/route?uid=TEST&page=3
# This will redirect to: https://domain.com/search/items?version=2&uid=TEST&page=3
```
</details>


### 🤝 Cross-platform

Since Checkpoint is made in Go and is using full cross-platform packages, it should run on any platform.

⚠️ Currently only tested on:
* Linux Fedora 36
* Kali Linux 2021.2

Feel free to test it on other platform and submit a merge request with updated [README.md](README.md).


## Installation

Clone the repo and build Checkpoint using Go.

```
git clone https://github.com/Atsika/checkpoint.git
cd checkpoint
go build
chmod +x checkpoint
```


## Usage

Once Checkpoint is built, you need to configure it through a configuration file (cf. [Simple configuration](#simple-configration)). Configuration file must be named `config.toml` and be placed in the same folder as Checkpoint. You can use the following command to make a copy of the example file:

```
cp example.config.toml config.toml
```

When you've finished completing the file with your values, simply run the binary using the following command :

```
./checkpoint
```


## TODO

* Blacklist IPs


## License

MIT License (see [LICENSE](LICENSE)).


## Author

Made with ❤️ by Atsika ([@_atsika](https://twitter.com/_atsika))