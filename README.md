# tnnlink
[![Build Status](https://travis-ci.org/LiljebergXYZ/tnnlink.svg?branch=master)](https://travis-ci.org/LiljebergXYZ/tnnlink)

Simple HTTP tunneling using SSH, authorized using github public keys.

Self-hosted ngrok alternative.

Visit [tnnl.ink](https://tnnl.ink) to see it in action.

## Connecting
```bash
ssh <github-username>@localhost -p 2222 -R 80:localhost:<local-port>
```

## Planned features (no order)
* TCP tunnel
* Custom sub-domain

## Dependencies
* [github.com/pelletier/go-toml](github.com/pelletier/go-toml)

## Usage
1. Install [Go](https://golang.org/doc/install)
2. Get the code
```bash
go get github.com/liljebergxyz/tnnlink
```
3. Compile & Install
```
go install github.com/liljebergxyz/tnnlink
```
4. Generate a passwordless host key
```
ssh-keygen -t rsa -b 4096 -f host_rsa
```
5. Create a config file
```
[http]
addr = ":8080"
sslAddr = ":4433"
mainDomain = ".localtest.me/"
ssl = false
cert = "./cert.pem"
key = "./key.pem"

[ssh]
addr = ":2222"
key = "./host_rsa"
whitelist = ""
```
6. Launch
```
tnnlink --config="./config.toml"
```

### Explanation of whitelist
The whitelist config entry is a comma-seperated list of github usernames

## Notes
1. This software has not been audited in anyway and was a fun weekend project I intend to continue supporting, but it is my first time writing a full application in Go for actual every-day use.
2. SSL is not activated by default and you are expected to generate a letsencrypt wildcard certificate in order to utilize it
