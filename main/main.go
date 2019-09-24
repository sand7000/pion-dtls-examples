package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	s "strings"
	"syscall"

	"net"
	"reflect"
	"strconv"
	"time"

	"github.com/pion/dtls"
	"github.com/pion/dtls/examples/util"
)

// BuffSize represents the size used to instantiate byte arrays
const BuffSize = 2000

// FlightSeconds is the flight retransmission timeout
const FlightSeconds = 100

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
	caMap["DISABLED"] = dtls.NoClientCert
	caMap["WANTED"] = dtls.RequestClientCert
	caMap["NEEDED"] = dtls.RequireAndVerifyClientCert

	// I wish Go had this function
	// os.setDefaultSockopts(syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println("Usage: go run main/main.go port_number [cipher_suite [client_auth [trust_cert]]]")
		return
	}
	port, _ := strconv.Atoi(args[0])
	fmt.Println("Port: ", port)

	// configuration variables
	var cipherSuiteID dtls.CipherSuiteID = dtls.TLS_PSK_WITH_AES_128_CCM_8
	var cipherSuiteName = "TLS_PSK_WITH_AES_128_CCM_8"
	var trustCert string = ""
	var clientAuth dtls.ClientAuthType = dtls.NoClientCert
	var contains bool

	if len(args) > 1 {
		cipherSuiteName = args[1]
		cipherSuiteID, contains = csMap[cipherSuiteName]
		if !contains {
			panic("Cipher suite " + cipherSuiteName + " not supported")
		}
		if len(args) > 2 {
			clientAuth, contains = caMap[args[2]]
			if !contains {
				panic("Client authentication mechanism " + args[2] + " not supported")
			}
			if len(args) > 3 {
				trustCert = args[3]
			}
		}
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
	if s.Contains(cipherSuiteName, "PSK") {
		config = &dtls.Config{
			PSK: func(hint []byte) ([]byte, error) {
				fmt.Printf("Client's hint: %s \n", hint)
				return []byte{0x12, 0x34}, nil
			},
			PSKIdentityHint:      []byte("Pion DTLS Client"),
			CipherSuites:         []dtls.CipherSuiteID{cipherSuiteID},
			FlightInterval:       FlightSeconds * time.Second,
			ExtendedMasterSecret: dtls.DisableExtendedMasterSecret,
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
			ExtendedMasterSecret: dtls.DisableExtendedMasterSecret,
			Certificate:          certificate,
			PrivateKey:           privateKey,
			ClientAuth:           clientAuth,
			RootCAs:              rootCAs,
		}
	}

	// Connect to a DTLS server
	listener, err := dtls.Listen("udp", addr, config)
	util.Check(err)

	// We define a deferred function to close the listener.
	// This function is called after the main method has ended
	defer func() {
		fmt.Println("Closing Listener")
		util.Check(listener.Close(0 * time.Second))
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL)
	go func() {
		for range c {
			fmt.Println("Received Signal")

			// Trying to kill server and the unbind address:

			// Attempt 1: kill via reflection by calling Close on the parent field.
			// It turned out that in golang you cannot call methods
			// on unexported fields
			// rl := reflect.ValueOf(listener)
			// fv := rl.Elem().FieldByName("parent")
			// examiner(fv.Type(), 2)

			// Attempt 2: call listener.Close.
			// Close blocks while Accept is blocking so it cannot be used.
			// util.Check(listener.Close(0 * time.Second))

			// Attempt 3: call os.exit
			// Bingo! Exit will terminate the main program and any goroutines
			os.Exit(0)
		}
	}()

	fmt.Println("Listening once")
	processOnce(listener)
}

func processOnce(listener *dtls.Listener) {
	fmt.Println("Ready to process")
	defer func() {
		fmt.Println("Finished Processing")
	}()
	conn, err := listener.Accept()
	fmt.Println("Exited Accept")
	if err == nil {
		//util.Check(err)
		handle(conn)
	}
}

func handle(conn net.Conn) {
	buffer := make([]byte, BuffSize)
	n, err := conn.Read(buffer)
	util.Check(err)
	fmt.Println("Read ", n)
	conn.Write(buffer)
}

// Helpful function copied from:
// https://medium.com/capital-one-tech/learning-to-use-go-reflection-822a0aed74b7
func examiner(t reflect.Type, depth int) {
	fmt.Println(strings.Repeat("\t", depth), "Type is", t.Name(), "and kind is", t.Kind())
	switch t.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Ptr, reflect.Slice:
		fmt.Println("NumMethods: ", t.NumMethod())
		for i := 0; i < t.NumMethod(); i++ {
			m := t.Method(i)
			fmt.Println(strings.Repeat("\t", depth+1), "Method", i+1, "name is", m.Name)
		}
		fmt.Println(strings.Repeat("\t", depth+1), "Contained type:")
		examiner(t.Elem(), depth+1)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			fmt.Println(strings.Repeat("\t", depth+1), "Field", i+1, "name is", f.Name, "type is", f.Type.Name(), "and kind is", f.Type.Kind())
			if f.Tag != "" {
				fmt.Println(strings.Repeat("\t", depth+2), "Tag is", f.Tag)
				fmt.Println(strings.Repeat("\t", depth+2), "tag1 is", f.Tag.Get("tag1"), "tag2 is", f.Tag.Get("tag2"))
			}
		}
	}
}
