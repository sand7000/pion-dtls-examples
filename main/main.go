package main

import (
	"fmt"
	"os"

	"net"
	"strconv"
	"time"

	"github.com/pion/dtls"
	"github.com/pion/dtls/examples/util"
)

const BUFF_SIZE = 2000
const DEF_RST_TIMEOUT = 10

func main() {
	// os.setDefaultSockopts(syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println("Usage: go run main/main.go port_number [rst_port_number [rst_timeout]]")
		return
	}
	port, _ := strconv.Atoi(args[0])
	fmt.Println("Port: ", port)
	var rstPort int = -1
	var rstTimeout int = DEF_RST_TIMEOUT
	if len(args) > 1 {
		rstPort, _ = strconv.Atoi(args[1])
		if len(args) > 1 {
			rstTimeout, _ = strconv.Atoi(args[2])
		}
	}

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
		PSKIdentityHint: []byte("Pion DTLS Client"),
		CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CCM_8},
		//ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ConnectTimeout: dtls.ConnectTimeoutOption(200 * time.Second),
	}

	// Connect to a DTLS server
	listener, err := dtls.Listen("udp", addr, config)
	util.Check(err)

	// We define a deferred function to close the listener.
	// This function is called after the main method has ended
	defer func() {
		fmt.Println("Closing Listener")
		util.Check(listener.Close(1 * time.Second))
	}()

	if rstPort == -1 {
		fmt.Println("Listening once")
		processOnce(listener)
	} else {
		rstAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: rstPort}
		rstConn, err := net.ListenUDP("udp", rstAddr)
		util.Check(err)
		var rstTimeoutDuration time.Duration = time.Duration(rstTimeout)
		readDeadline := time.Now().Add(rstTimeoutDuration * time.Second)
		rstConn.SetReadDeadline(readDeadline)
		for {
			buffer := make([]byte, BUFF_SIZE)
			_, err = rstConn.Read(buffer)
			util.Check(err)
			go func() {
				processOnce(listener)
			}()
		}
	}
}

func processOnce(listener *dtls.Listener) {
	conn, err := listener.Accept()
	util.Check(err)
	handle(conn)
}

func handle(conn net.Conn) {
	buffer := make([]byte, BUFF_SIZE)
	n, err := conn.Read(buffer)
	util.Check(err)
	fmt.Println("Read ", n)
	conn.Write(buffer)
}
