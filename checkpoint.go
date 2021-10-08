package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Struct used for user configuration
type Config struct {
	Certs struct {
		Crt string
		Key string
	}
	Redirect struct {
		Success string
		Fail    string
	}
	Recaptcha struct {
		SiteKey    string
		PrivateKey string
	}
	Parameters []string
	Decoy      string
}

// Struct used to organise front data (when sent to /verify)
type Front struct {
	Token string
	Url   string
}

// Struct used to fill html template
type TemplateData struct {
	SiteKey  string
	IP       string
	URL      string
	DateTime string
}

// Global variable containing configuration
var conf Config

// Only cool projects got a banner
func banner() {
	checkpoint := `

     ____ _   _ _____ ____ _  ______   ___ ___ _   _ _____ 
    / ___| | | | ____/ ___| |/ /  _ \ / _ \_ _| \ | |_   _|
   | |   | |_| |  _|| |   | ' /| |_) | | | | ||  \| | | |  
   | |___|  _  | |__| |___| . \|  __/| |_| | || |\  | | |  
    \____|_| |_|_____\____|_|\_\_|    \___/___|_| \_| |_|  
                                                           

                made with ❤️ by @_atsika

`
	fmt.Print(checkpoint)
}

// Retrieve configuration from file
func getConfig() bool {
	c, err := ioutil.ReadFile("config.json")
	if err != nil {
		return false
	}

	err = json.Unmarshal(c, &conf)
	if err != nil {
		return false
	}

	return true
}

// Configure TLS 1.3 with recommanded cipher suites
func configTls(mux *mux.Router) *http.Server {
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
		Addr:         ":https",
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	return srv
}

// Build good redirection url with parameters
func buildUrl(oldUrl string, newUrl string) string {
	o, err := url.Parse(oldUrl)
	if err != nil {
		return ""
	}

	n, err := url.Parse(newUrl)
	if err != nil {
		return ""
	}

	return n.Scheme + "://" + n.Host + n.Path + o.RawQuery
}

// Check if required parameters are in url using regex
func checkRequiredParams(frontUrl string) bool {
	parsedUrl, _ := url.Parse(frontUrl)
	params, _ := url.ParseQuery(parsedUrl.RawQuery)

	for _, v := range conf.Parameters {
		if _, ok := params[v]; !ok {
			return false
		}
	}
	return true
}

// Handle all incoming requests
func handleRequest(w http.ResponseWriter, req *http.Request) {
	// HSTS
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

	// This branch is used to verify reCAPTCHA token and then redirect
	if req.URL.Path == "/verify" && req.Method == "POST" {

		status := false
		var front Front

		verification, err := ioutil.ReadAll(req.Body)
		if err != nil {
			goto RETURN
		}
		{
			err = json.Unmarshal(verification, &front)
			if err != nil {
				goto RETURN
			}

			if !checkRequiredParams(front.Url) {
				goto RETURN
			}

			// Set post parameters to send to Google for verification
			form := url.Values{
				"secret":   {conf.Recaptcha.PrivateKey},
				"response": {front.Token},
			}
			resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify", form)
			if err != nil {
				goto RETURN
			}

			content, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				goto RETURN
			}

			// Parse API response (https://developers.google.com/recaptcha/docs/verify#api-response)
			var apiResponse map[string]json.RawMessage
			err = json.Unmarshal(content, &apiResponse)
			if err != nil {
				goto RETURN
			}

			err = json.Unmarshal(apiResponse["success"], &status)
			if err != nil {
				goto RETURN
			}
		}
		// This is where we return either the good url or a dummy redirection
	RETURN:
		if status {
			goodUrl := buildUrl(front.Url, conf.Redirect.Success)
			w.Write([]byte(goodUrl))
		} else {
			w.Write([]byte(conf.Redirect.Fail))
		}
		return

		// This branch is used for initial connection
	} else {

		// RemoteAddr format is IP:PORT, we just need IP
		pos := strings.LastIndex(req.RemoteAddr, ":")
		ip := req.RemoteAddr[:pos]
		// Prepare structure
		reqi := TemplateData{SiteKey: conf.Recaptcha.SiteKey, IP: ip, URL: conf.Decoy, DateTime: time.Now().Format(time.RFC3339)}

		// Fill template
		t, err := template.ParseFiles("templates/index.html")
		if err != nil {
			panic(err)
		}

		// Return filled template
		t.Execute(w, reqi)

	}
}

// Entrypoint
func main() {

	banner()

	// Read config from file
	if !getConfig() {
		log.Fatal("An error occured while trying to read config file.")
		return
	}

	// Create new router
	r := mux.NewRouter()

	// This will catch any route
	r.PathPrefix("/").HandlerFunc(handleRequest)

	// Configure TLS
	srv := configTls(r)

	// Start listening
	log.Fatal(srv.ListenAndServeTLS(conf.Certs.Crt, conf.Certs.Key))
}
