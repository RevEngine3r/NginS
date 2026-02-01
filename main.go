package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/RevEngine3r/NginS/handlers"
	"github.com/RevEngine3r/NginS/internal/socks5"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		HttpHost  string `yaml:"httpHost"`
		HttpPort  string `yaml:"httpPort"`
		HttpsHost string `yaml:"httpsHost"`
		HttpsPort string `yaml:"httpsPort"`
	} `yaml:"server"`
	Proxy struct {
		Socks5Host string `yaml:"socks5Host"`
		Socks5Port string `yaml:"socks5Port"`
		Username   string `yaml:"username"`
		Password   string `yaml:"password"`
	} `yaml:"proxy"`
}

var (
	config       Config
	configFile   *string
	socks5Client *socks5.Client
)

func readConfig() {
	data, err := os.ReadFile(*configFile + ".yml")
	if err != nil {
		log.Fatalf("failed to read config file: %v", err)
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("failed to unmarshal config: %v", err)
	}
}

func init() {
	configFile = flag.String("C", "config", "Config File Path (without .yml)")
}

func main() {
	flag.Parse()

	if flag.NFlag() == 0 {
		flag.Usage()
	}

	readConfig()

	socks5Client = &socks5.Client{
		ProxyAddr: net.JoinHostPort(config.Proxy.Socks5Host, config.Proxy.Socks5Port),
		Username:  config.Proxy.Username,
		Password:  config.Proxy.Password,
	}

	var wg sync.WaitGroup

	// HTTP Listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		listenAndServe(config.Server.HttpHost, config.Server.HttpPort, false)
	}()

	// HTTPS Listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		listenAndServe(config.Server.HttpsHost, config.Server.HttpsPort, true)
	}()

	wg.Wait()
}

func listenAndServe(host, port string, isHttps bool) {
	addr := net.JoinHostPort(host, port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", addr, err)
	}
	defer l.Close()

	scheme := "Http"
	if isHttps {
		scheme = "Https"
	}
	log.Printf("%s Server Listening on: %s", scheme, addr)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			time.Sleep(time.Second)
			continue
		}
		go handleConnection(conn.(*net.TCPConn), isHttps)
	}
}

func handleConnection(clientConn *net.TCPConn, isHttps bool) {
	defer clientConn.Close()

	serverName, clientReader, err := peekServerName(clientConn, isHttps)
	if err != nil {
		log.Printf("peek error: %v", err)
		return
	}

	if serverName == "" {
		log.Printf("rejected: missing SNI/Host header")
		return
	}

	log.Printf("routing %s -> SOCKS5", serverName)

	dstPort := config.Server.HttpPort
	if isHttps {
		dstPort = config.Server.HttpsPort
	}

	backendConn, err := socks5Client.Dial(net.JoinHostPort(serverName, dstPort))
	if err != nil {
		log.Printf("socks5 dial error for %s: %v", serverName, err)
		return
	}
	defer backendConn.Close()

	copyStreams(clientConn, backendConn.(*net.TCPConn), clientReader)
}

func peekServerName(clientConn *net.TCPConn, isHttps bool) (string, io.Reader, error) {
	if isHttps {
		return handlers.PeekClientHello(clientConn)
	}
	return handlers.PeekHttpReq(clientConn)
}

func copyStreams(clientConn *net.TCPConn, backendConn *net.TCPConn, clientReader io.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Backend to Client
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, backendConn)
		_ = backendConn.CloseRead()
		_ = clientConn.CloseWrite()
	}()

	// Client to Backend
	go func() {
		defer wg.Done()
		_ = clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, _ = io.Copy(backendConn, clientReader)
		_ = clientConn.CloseRead()
		_ = backendConn.CloseWrite()
	}()

	wg.Wait()
}
