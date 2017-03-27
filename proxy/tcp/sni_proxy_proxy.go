package tcp

import (
	"io"
	"fmt"
	"log"
	"net"
	"time"
)

// SNIProxyProxy implements an SNI aware TCP proxy using Proxy protocol
// which captures the TLS client hello, extracts the host name and uses it
// for finding the upstream server. Then it sends a PROXY Protocol header,
// replays the ClientHello message and copies data transparently allowing
// to route a TLS connection based on the SNI header without decrypting it.
type SNIProxyProxy struct {
	// DialTimeout sets the timeout for establishing the outbound
	// connection.
	DialTimeout time.Duration

	// Lookup returns a target host for the given server name.
	// The proxy will panic if this value is nil.
	Lookup func(host string) string
}

func (p *SNIProxyProxy) ServeTCP(in net.Conn) error {
	defer in.Close()

	// capture client hello
	data := make([]byte, 1024)
	n, err := in.Read(data)
	if err != nil {
		return err
	}
	data = data[:n]

	host, ok := readServerName(data)
	if !ok {
		log.Print("[DEBUG] tcp+sni+proxy: TLS handshake failed")
		return nil
	}

	if host == "" {
		log.Print("[DEBUG] tcp+sni+proxy: server_name missing")
		return nil
	}

	addr := p.Lookup(host)
	if addr == "" {
		return nil
	}

	out, err := net.DialTimeout("tcp", addr, p.DialTimeout)
	if err != nil {
		log.Print("[WARN] tcp+sni+proxy: cannot connect to upstream ", addr)
		return err
	}
	defer out.Close()

	// send PROXY protocol header
	source_addr, source_port, err := net.SplitHostPort(in.RemoteAddr().String())
	if err != nil {
		log.Print("[WARN] tcp+sni+proxy: parsing source address has failed. ", err)
		return err
	}

	dest_addr, dest_port, err := net.SplitHostPort(addr)
	if err != nil {
		log.Print("[WARN] tcp+sni+proxy: parsing destination address has failed. ", err)
		return err
	}

	header := fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", source_addr, dest_addr, source_port, dest_port)
	_, err = out.Write([]byte(header))
	if err != nil {
		log.Print("[WARN] tcp+sni+proxy: sending PROXY protocol header failed. ", err)
		return err
	}

	// copy client hello
	_, err = out.Write(data)
	if err != nil {
		log.Print("[WARN] tcp+sni+proxy: copy client hello failed. ", err)
		return err
	}

	errc := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errc <- err
	}

	go cp(out, in)
	go cp(in, out)
	err = <-errc
	if err != nil && err != io.EOF {
		log.Print("[WARN]: tcp+sni+proxy:  ", err)
		return err
	}
	return nil
}
