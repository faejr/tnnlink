package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

const (
	forwardedTCPChannelType = "forwarded-tcpip"
)

type SSHServer struct {
	config   *ssh.ServerConfig
	vhosts   map[net.Addr]*VHost
	users    []string
	forwards map[string]net.Listener
	sync.RWMutex
}

type RemoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type RemoteForwardSuccess struct {
	BindPort uint32
}

type RemoteForwardCancelRequest struct {
	BindAddr string
	BindPort uint32
}

type RemoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// Starts the SSH Server
func (server *SSHServer) Start(mux *ProxyMux) {
	log.Println("Starting SSH server...")

	// You may also explicitly allow anonymous client authentication
	// server.config.NoClientAuth = true
	server.config = &ssh.ServerConfig{
		PublicKeyCallback: publicKeyAuthStrategy,
	}
	server.vhosts = make(map[net.Addr]*VHost)

	// You can generate a keypair with 'ssh-keygen -t rsa'
	privateBytes, err := ioutil.ReadFile(sshServerKeyPath)
	if err != nil {
		log.Fatalf("Failed to load private key (./%s)", sshServerKeyPath)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	server.config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", sshListenPort)
	if err != nil {
		log.Fatalf("Failed to listen on %s (%s)", sshListenPort, err)
	}

	// Accept all connections
	log.Printf("Listening on %s...", sshListenPort)
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}

		log.Printf("Beginning SSH handshake for %s", tcpConn.RemoteAddr())

		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, server.config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		// Handle requests
		go server.handleRequests(reqs, sshConn, mux)
		// Accept all channels
		go server.handleChannels(chans, sshConn, mux)
	}
}

func publicKeyAuthStrategy(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	convertPublicKeyToString := func(key ssh.PublicKey) string {
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	}

	publicKey := convertPublicKeyToString(key)

	user := conn.User()

	if whitelist.users != nil {
		if !contains(whitelist.users, user) {
			return nil, errors.New("User not in whitelist")
		}
	}

	githubKeys := getPublicKeys(user)
	if githubKeys != nil {
		for _, key := range githubKeys {
			if publicKey == key {
				log.Printf("Successfully authenticated %s@%s", conn.User(), conn.RemoteAddr())
				return &ssh.Permissions{}, nil
			}
		}
		log.Printf("Unauthorized access from %s@%s", conn.User(), conn.RemoteAddr())
		return nil, errors.New("Unauthorized access")
	}

	log.Printf("Unauthorized access from %s@%s", conn.User(), conn.RemoteAddr())
	return nil, errors.New("Unauthorized access")
}

func (server *SSHServer) handleChannels(chans <-chan ssh.NewChannel, conn *ssh.ServerConn, mux *ProxyMux) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go server.handleChannel(newChannel, conn, mux)
	}
}

func (server *SSHServer) handleRequests(reqs <-chan *ssh.Request, conn *ssh.ServerConn, mux *ProxyMux) {
	server.Lock()
	if server.forwards == nil {
		server.forwards = make(map[string]net.Listener)
	}
	server.Unlock()

	port, err := getFreePort()
	if err != nil {
		log.Fatal(err)
	}

	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			var reqPayload RemoteForwardRequest
			if err := ssh.Unmarshal(req.Payload, &reqPayload); err != nil {
				// TODO: log parse failure
				req.Reply(false, []byte{})
			}

			addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(port))
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				// TODO: log listen failure
				req.Reply(false, []byte{})
			}

			server.Lock()
			server.forwards[addr] = ln
			server.Unlock()

			subdomain := randStringBytesMaskImprSrc(5)

			for {
				var found = false
				for _, vhost := range server.vhosts {
					if vhost.Subdomain == subdomain {
						subdomain = randStringBytesMaskImprSrc(5)
						found = true
						break
					}
				}
				if found {
					continue
				}
				break
			}

			// Setup vhost
			vhost, err := url.Parse("http://" + addr)
			if err != nil {
				panic(err)
			}
			proxy := httputil.NewSingleHostReverseProxy(vhost)
			mux.HandleFunc(subdomain+mainDomain, proxyHandler(proxy))

			// Add and save the vhost in our server object
			server.Lock()
			server.vhosts[conn.RemoteAddr()] = &VHost{
				User:      conn.User(),
				Subdomain: subdomain,
				Addr:      addr,
			}
			server.Unlock()

			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						// TODO: log accept failure
						log.Println("accept:", err)
						break
					}
					originAddr, orignPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
					originPort, _ := strconv.Atoi(orignPortStr)
					payload := ssh.Marshal(&RemoteForwardChannelData{
						DestAddr:   reqPayload.BindAddr,
						DestPort:   reqPayload.BindPort,
						OriginAddr: originAddr,
						OriginPort: uint32(originPort),
					})
					go func() {
						ch, reqs, err := conn.OpenChannel(forwardedTCPChannelType, payload)
						if err != nil {
							// TODO: log failure to open channel
							log.Println(err)
							c.Close()
							return
						}
						go ssh.DiscardRequests(reqs)
						go func() {
							defer ch.Close()
							defer c.Close()
							io.Copy(ch, c)
						}()
						go func() {
							defer ch.Close()
							defer c.Close()
							io.Copy(c, ch)
						}()
					}()
				}
				server.Lock()
				delete(server.forwards, addr)
				server.Unlock()
			}()
			req.Reply(true, ssh.Marshal(&RemoteForwardSuccess{reqPayload.BindPort}))

		case "cancel-tcpip-forward":
			var reqPayload RemoteForwardCancelRequest
			if err := ssh.Unmarshal(req.Payload, &reqPayload); err != nil {
				// TODO: log parse failure
				req.Reply(false, []byte{})
			}
			addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(port))
			server.Lock()
			ln, ok := server.forwards[addr]
			server.Unlock()
			if ok {
				ln.Close()
			}
			req.Reply(true, []byte{})
		default:
			req.Reply(false, []byte{})
		}
	}
}

// Handle the session SSH channel
func (server *SSHServer) handleChannel(newChannel ssh.NewChannel, conn *ssh.ServerConn, mux *ProxyMux) {
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	// Wait and get subdomain for connection
	// Then send information to user
	for {
		server.Lock()
		vhost, ok := server.vhosts[conn.RemoteAddr()]
		server.Unlock()
		if ok {
			var subdomainText bytes.Buffer
			subdomainText.WriteString("\x1b[32mForwarding HTTP traffic from \x1b[4m")
			if sslActive {
				subdomainText.WriteString("https")
			} else {
				subdomainText.WriteString("http")
			}
			subdomainText.WriteString("://")
			subdomainText.WriteString(vhost.Subdomain)
			subdomainText.WriteString(mainDomain)
			subdomainText.WriteString("\x1b[24m\x1b[39m\r\nPress ctrl-c to quit\r\n")
			connection.Write(subdomainText.Bytes())
			break
		}
	}

	// Prepare teardown function
	close := func() {
		server.Lock()
		vhost, ok := server.vhosts[conn.RemoteAddr()]
		if ok {
			ln, ok := server.forwards[vhost.Addr]
			if ok {
				ln.Close()
			}
			mux.Deregister(vhost.Subdomain + mainDomain)
		}
		server.Unlock()
		connection.Close()
		log.Printf("Session closed")
	}

	go func() {
		for {
			reader := bufio.NewReader(connection)
			result, _, err := reader.ReadRune()
			if err != nil {
				log.Println(err)
				return
			}
			switch result {
			case 3: // ctrl-c
				close()
				return
			}
		}
	}()

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			}
		}
	}()
}
