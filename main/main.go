package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"net"
	"time"

	"github.com/pion/dtls"
	"github.com/pion/dtls/examples/util"
)

// BuffSize represents the size used to instantiate byte arrays
const BuffSize = 2000

// FlightSeconds is the flight retransmission timeout
const FlightSeconds = 100

const (
	// Server role
	Server string = "server"
	// Client role
	Client string = "client"
)

const (
	// DISABLED Client certificate authentication is disabled
	DISABLED string = "DISABLED"
	// WANTED Client certificate is requested but not required
	WANTED string = "WANTED"
	// NEEDED Client certificate is requested and required
	NEEDED string = "NEEDED"
)

const (
	// Complete handshake and exit
	BASIC string = "BASIC"
	// Echo once and exit
	ONE_ECHO string = "ONE_ECHO"
	// Continuous echo
	FULL string = "FULL"
)

// this is a very dirty go harness

func main() {

	// create map of supported cipher suites
	csMap := make(map[string]dtls.CipherSuiteID)
	csMap["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"] = dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	csMap["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"] = dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	csMap["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"] = dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	csMap["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"] = dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	csMap["TLS_PSK_WITH_AES_128_CCM_8"] = dtls.TLS_PSK_WITH_AES_128_CCM_8
	csMap["TLS_PSK_WITH_AES_128_GCM_SHA256"] = dtls.TLS_PSK_WITH_AES_128_GCM_SHA256

	// create map of supported client authentication types
	caMap := make(map[string]dtls.ClientAuthType)
	caMap[DISABLED] = dtls.NoClientCert
	caMap[WANTED] = dtls.RequestClientCert
	caMap[NEEDED] = dtls.RequireAndVerifyClientCert

	// commmand line/configuration variables
	var port int
	var role string
	var cipherSuiteName string
	var cipherSuiteID dtls.CipherSuiteID = dtls.TLS_PSK_WITH_AES_128_CCM_8
	var clientAuthName string
	var clientAuth dtls.ClientAuthType = dtls.NoClientCert
	var trustCert string = ""
	var operation string = ""
	var help bool
	var serverName = ""

	flag.StringVar(&role, "role", "server", "Role {client,server}")
	flag.IntVar(&port, "port", 0, "Listening port the in case of servers/connect port in the case of clients (Required)")
	flag.StringVar(&cipherSuiteName, "cipherSuite", "TLS_PSK_WITH_AES_128_CCM_8", "Cipher suite to use {TLS_PSK_WITH_AES_128_CCM_8, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ..}")
	flag.StringVar(&clientAuthName, "clientAuth", DISABLED, "Client authentication settings {DISABLED, NEEDED, WANTED}")
	flag.StringVar(&operation, "operation", FULL, "Mode of operation {BASIC, ONE_ECHO, FULL}. BASIC means exit after handshake completion, ONE_ECHO means echo once, FULL means echo continuously until something bad happens.")
	flag.StringVar(&trustCert, "trustCert", "", "Certificate(s) in .pem format of CAs a side trusts, used to check certificate received from the other peer.")
	flag.StringVar(&serverName, "serverName", "", "The name the client uses to validate the certificate received from the server")
	flag.BoolVar(&help, "help", false, "Show usage screen")

	flag.Parse()

	if help {
		flag.PrintDefaults()
		return
	}

	if port == 0 {
		fmt.Println("No port has been provided")
		flag.PrintDefaults()
		return
	}

	if role != Client && role != Server {
		panic("Role " + role + " is invalid")
	}

	var contains bool

	cipherSuiteID, contains = csMap[cipherSuiteName]
	if !contains {
		panic("Cipher suite " + cipherSuiteName + " not supported")
	}

	clientAuth, contains = caMap[clientAuthName]
	if !contains {
		panic("Client authentication mechanism " + clientAuthName + " not supported")
	}

	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}

	fmt.Println("Using cipher suite ", cipherSuiteName, " with id ", cipherSuiteID)

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// Prepare the configuration of the DTLS connection
	// Note that PSK and ECDHE cipher suites cannot be combined
	var config *dtls.Config

	if strings.Contains(cipherSuiteName, "PSK") {
		config = &dtls.Config{
			PSK: func(hint []byte) ([]byte, error) {
				fmt.Printf("Client's hint: %s \n", hint)
				return []byte{0x12, 0x34}, nil
			},
			PSKIdentityHint:      []byte("Pion DTLS Client"),
			CipherSuites:         []dtls.CipherSuiteID{cipherSuiteID},
			FlightInterval:       FlightSeconds * time.Second,
		}
	} else {
		// Generate a certificate and private key to secure the connection
		certificate, privateKey, err := dtls.GenerateSelfSigned()
		util.Check(err)

		// If a trusted certficate was provided, fetch it
		var rootCAs *x509.CertPool = nil
		if len(trustCert) > 0 {
			dat, err := ioutil.ReadFile(trustCert)
			util.Check(err)
			rootCAs = x509.NewCertPool()
			succ := rootCAs.AppendCertsFromPEM(dat)
			if !succ {
				panic("Was not successful in parsing certificate")
			}
		}

		config = &dtls.Config{
			CipherSuites:         []dtls.CipherSuiteID{cipherSuiteID},
			FlightInterval:       FlightSeconds * time.Second,
			Certificate:          certificate,
			PrivateKey:           privateKey,
			ClientAuth:           clientAuth,
			RootCAs:              rootCAs,
			ServerName:           serverName,
		}
	}

	if role == Server {
		// Bind to server listening address
		listener, err := dtls.Listen("udp", addr, config)
		util.Check(err)

		// We define a deferred function to close the listener.
		// This function is called after the main method has ended
		defer func() {
			fmt.Println("Closing Listener")
			util.Check(listener.Close())
		}()

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL)
		go func() {
			for range c {
				fmt.Println("Received Signal")
				os.Exit(0)
			}
		}()

		fmt.Println("Listening once")
		processOnce(listener, operation)
	} else if role == Client {
		// Connect to a DTLS server
		conn, err := dtls.Dial("udp", addr, config)
		util.Check(err)
		handle(conn, operation)
	}
}

func processOnce(listener *dtls.Listener, operation string) {
	fmt.Println("Ready to process")
	defer func() {
		fmt.Println("Finished Processing")
	}()
	conn, err := listener.Accept()
	fmt.Println("Exited Accept")
	if err == nil {
		//util.Check(err)
		handle(conn, operation)
	}
}

func handle(conn net.Conn, operation string) {
	if operation != BASIC {
		buffer := make([]byte, BuffSize)
		for true {
			n, err := conn.Read(buffer)
			util.Check(err)
			fmt.Println("Read ", n)
			conn.Write(buffer)
			if operation == ONE_ECHO {
				break
			}
		}
	}
}
