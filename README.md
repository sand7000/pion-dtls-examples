# pion-dtls-examples
Go PionDTLS example programs used to test DTLS client/server implementations. 
Currently, the only example included is a harness which can be configured to operate as a DTLS client or server.
In either case, the harness completes a handshake, echoes exactly one application message before terminating.

# Setting up

Install go version 1.13 or later which comes with support for modules, which makes setting up a lot easier.

Deploy the desired version of PionDTLS. The harness should be compatible with v1.5.2, and may be compatible with newer versions with minimal edits. 

> go get github.com/pion/dtls@v1.5.2

Run the harness (to get the usage page).

> go run main/main.go

Alternatively, once PionDTLS is set up, you can compile and run the resulting binaries:

> go build -o main/main main/main.go 

> main/main

