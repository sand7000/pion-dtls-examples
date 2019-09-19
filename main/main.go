package main

import (
	"fmt"
	"os"
	//"bytes"
	"net"
	"time"
	"strconv"

	"github.com/pion/dtls"
	"github.com/pion/dtls/examples/util"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println("Usage go run main/main.go port_number")
		return
	}
	port, _ := strconv.Atoi(args[0])
	fmt.Println("Port: ",port)

	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			fmt.Printf("Client's hint: %s \n", hint)
			return []byte{0x12, 0x34}, nil
		},
		PSKIdentityHint:      []byte("Pion DTLS Client"),
		CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CCM_8},
		//ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ConnectTimeout:       dtls.ConnectTimeoutOption(200 * time.Second),
	}

	// Connect to a DTLS server
	listener, err := dtls.Listen("udp", addr, config)
	util.Check(err)
	defer func() {
		util.Check(listener.Close(5 * time.Second))
	}()

	fmt.Println("Listening softly")

	conn, err := listener.Accept()
	buffer := make([]byte, 2000)
	n, err := conn.Read(buffer)
	util.Check(err)
	fmt.Println("Read ",n)
	conn.Write(buffer)
}
