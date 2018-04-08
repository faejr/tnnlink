package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/pelletier/go-toml"
)

var (
	httpListenPort   = ":8080"
	sslListenPort    = ":4433"
	sshListenPort    = ":2222"
	sshServerKeyPath = "/etc/tnnlink/host_rsa"
	mainDomain       = ".localtest.me"
	sslActive        = false
	sslCert          = "/etc/tnnlink/cert.pem"
	sslKey           = "/etc/tnnlink/key.pem"
	whitelist        = &Whitelist{}
)

type Whitelist struct {
	users []string
}

type VHost struct {
	User      string
	Subdomain string
	Addr      string
	TCP       bool
	Port      int
}

func main() {
	configPath := flag.String("config", "/etc/tnnlink/config.toml", "Set config path")

	flag.Parse()

	// Load configuration
	config, err := toml.LoadFile(*configPath)
	if err != nil {
		log.Fatal(err)
		return
	}

	httpListenPort = config.GetDefault("http.addr", httpListenPort).(string)
	sslListenPort = config.GetDefault("http.sslAddr", sslListenPort).(string)
	sshListenPort = config.GetDefault("ssh.addr", sshListenPort).(string)
	sshServerKeyPath = config.GetDefault("ssh.key", sshServerKeyPath).(string)
	mainDomain = config.GetDefault("http.mainDomain", mainDomain).(string)
	sslCert = config.GetDefault("http.cert", sslCert).(string)
	sslKey = config.GetDefault("http.key", sslKey).(string)
	sslActive = config.GetDefault("http.ssl", sslActive).(bool)
	userlist := config.GetDefault("ssh.whitelist", "").(string)
	if userlist != "" {
		whitelist.users = strings.Split(userlist, ",")
	}

	var sshServer = &SSHServer{}
	mux := new(ProxyMux)

	// Setup SSL Server
	if sslActive {
		tlsSrv := &http.Server{
			Addr:    sslListenPort,
			Handler: mux,
		}

		// Start HTTP server
		go func() {
			//proxyHandler
			err := tlsSrv.ListenAndServeTLS(sslCert, sslKey)
			if err != nil {
				panic(err)
			}
		}()
	}

	// Setup HTTP server
	srv := &http.Server{
		Addr:    httpListenPort,
		Handler: mux,
	}
	go func() {
		//proxyHandler
		err := srv.ListenAndServe()
		if err != nil {
			panic(err)
		}
	}()

	// Start SSH Server
	sshServer.Start(mux)
}

// HTTP Handler to handle reverse proxy requests
func proxyHandler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		p.ServeHTTP(w, r)
	}
}
