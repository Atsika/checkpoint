package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"text/template"

	conf "checkpoint/configuration"
	middle "checkpoint/middlewares"

	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
)

// Struct used to organise front data (when sent to /verify)
type Front struct {
	Token string `json:"token"`
	Url   string `json:"url"`
}

var config = &conf.Config

// Entrypoint
func main() {
	// Configure log output
	log.SetFormatter(&log.TextFormatter{TimestampFormat: "2006-01-02 15:04:05", FullTimestamp: true, ForceQuote: true, QuoteEmptyFields: true, DisableColors: true})

	// Display the cool banner
	banner()

	// Read config from file
	conf.Parse("config.toml")

	// Create new router
	r := mux.NewRouter()

	// This will catch any route except the ones we have defined
	r.NotFoundHandler = http.HandlerFunc(handleNotFound)

	// The route we want the user to query
	r.HandleFunc(config.Match.Route, handleRequest).
		Methods(http.MethodGet).
		Queries(config.Match.Parameters...)

		// Handle captcha verification
	r.HandleFunc("/verify", handleCaptcha).
		Methods(http.MethodPost)

	// Add all middlewares
	middle.AddMiddlewares(r)

	// Configure TLS
	srv := NewHTTPSServer(r)

	// Start listening
	log.Fatal(srv.ListenAndServeTLS(config.Tls.Cert, config.Tls.Key))
}

// Only cool projects got a banner
func banner() {
	checkpoint := `

     ____ _   _ _____ ____ _  ______   ___ ___ _   _ _____ 
    / ___| | | | ____/ ___| |/ /  _ \ / _ \_ _| \ | |_   _|
   | |   | |_| |  _|| |   | ' /| |_) | | | | ||  \| | | |  
   | |___|  _  | |__| |___| . \|  __/| |_| | || |\  | | |  
    \____|_| |_|_____\____|_|\_\_|    \___/___|_| \_| |_|  
                                                           

                made with ❤️  by @_atsika

`
	fmt.Print(checkpoint)
}

// Configure TLS 1.3 with recommanded cipher suites
func NewHTTPSServer(mux *mux.Router) *http.Server {
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	srv := &http.Server{
		Addr:         config.Listen,
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	return srv
}

func handleNotFound(w http.ResponseWriter, r *http.Request) {
	logReq("invalid route", log.WarnLevel, r)
	http.Redirect(w, r, config.Redirect.Bad, http.StatusMovedPermanently)
}

func handleCaptcha(w http.ResponseWriter, r *http.Request) {
	status := false
	var front Front

	verification, err := io.ReadAll(r.Body)
	if err != nil {
		goto REDIRECT
	}
	{
		err = json.Unmarshal(verification, &front)
		if err != nil {
			goto REDIRECT
		}

		// Set post parameters to send to Google for verification
		form := url.Values{
			"secret":   {config.Captcha.PrivateKey},
			"response": {front.Token},
		}

		resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify", form)
		if err != nil {
			goto REDIRECT
		}

		content, err := io.ReadAll(resp.Body)
		if err != nil {
			goto REDIRECT
		}

		// Parse API response (https://developers.google.com/recaptcha/docs/verify#api-response)
		var apiResponse map[string]json.RawMessage
		err = json.Unmarshal(content, &apiResponse)
		if err != nil {
			goto REDIRECT
		}

		err = json.Unmarshal(apiResponse["success"], &status)
		if err != nil {
			goto REDIRECT
		}
	}
	// This is where we return either the good url or a dummy redirection
REDIRECT:
	if status {
		logReq("captcha solved", log.InfoLevel, r)
		goodUrl := buildURL(front.Url)
		w.Write([]byte(goodUrl))
	} else {
		logReq("bot detected", log.ErrorLevel, r)
		w.Write([]byte(config.Redirect.Bad))
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	logReq("valid route", log.InfoLevel, r)
	captchaVersion := strconv.Itoa(config.Captcha.Version)

	// Fill the right template
	t, err := template.ParseFiles("static/captcha" + captchaVersion + ".html")
	if err != nil {
		panic(err)
	}

	// Return filled template
	t.Execute(w, struct{ SiteKey string }{config.Captcha.SiteKey})
}

// Build good redirection url with parameters
func buildURL(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	parsedQuery, err := url.ParseQuery(parsedURL.RawQuery)
	if err != nil {
		return ""
	}

	goodURL, err := url.Parse(config.Redirect.Good)
	if err != nil {
		return ""
	}

	goodQuery, err := url.ParseQuery(goodURL.RawQuery)
	if err != nil {
		return ""
	}

	for k := range parsedQuery {
		goodQuery[k] = parsedQuery[k]
	}

	return goodURL.Scheme + "://" + goodURL.Host + goodURL.Path + "?" + goodQuery.Encode()
}

func logReq(msg string, level log.Level, r *http.Request) {
	fields := log.Fields{
		"ip":     r.RemoteAddr,
		"method": r.Method,
		"route":  r.URL.Path,
	}

	params := r.URL.Query()
	for i, v := range config.Match.Parameters {
		if i%2 != 0 {
			continue
		}

		if len(params[v]) != 0 {
			fields[v] = params[v][0]
		} else {
			fields[v] = ""
		}
	}

	log.WithFields(fields).Log(level, msg)
}
