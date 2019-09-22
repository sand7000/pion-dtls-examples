package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"net"
	"reflect"
	"strconv"
	"time"

	"github.com/pion/dtls"
	"github.com/pion/dtls/examples/util"
)

// BuffSize representize the size used to instantiate byte arrays
const BuffSize = 2000

// DefRstTimeout represents the default timeout before the reset socket is closed
const DefRstTimeout = 10

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
	var rstTimeout int = DefRstTimeout
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
		//ConnectTimeout: dtls.ConnectTimeoutOption(200 * time.Second),
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
			rl := reflect.ValueOf(listener)
			fv := rl.Elem().FieldByName("parent")
			examiner(fv.Type(), 2)
			os.Exit(0)
			//util.Check(listener.Close(0 * time.Second))
		}
	}()

	if rstPort == -1 {
		fmt.Println("Listening once")
		processOnce(listener)
	} else {
		rstAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: rstPort}
		rstConn, err := net.ListenUDP("udp", rstAddr)
		util.Check(err)
		for {
			buffer := make([]byte, BuffSize)
			var rstTimeoutDuration time.Duration = time.Duration(rstTimeout)
			readDeadline := time.Now().Add(rstTimeoutDuration * time.Second)
			rstConn.SetReadDeadline(readDeadline)
			_, err = rstConn.Read(buffer)
			util.Check(err)
			fmt.Println("Received command to process")

			go func() {
				processOnce(listener)
			}()
		}
	}
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
