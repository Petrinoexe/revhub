package mgmt

import (
	"net"
	"testing"
	"time"

	"revhub/internal/model"
)

func TestAddrsPrefersTunnel(t *testing.T) {
	st := model.Demo()
	var exit model.Node
	for _, n := range st.Nodes {
		if n.ID == "exit-eu" {
			exit = n
		}
	}
	addrs := Addrs(st, exit)
	if len(addrs) != 2 {
		t.Fatalf("адреса = %v", addrs)
	}
	if addrs[0] != "10.77.1.2:22" {
		t.Errorf("первым должен идти адрес в туннеле, получено %v", addrs)
	}
	if addrs[1] != "eu.example.com:22" {
		t.Errorf("запасной адрес = %q", addrs[1])
	}
}

func TestAddrsFallsBackWhenNoTunnel(t *testing.T) {
	st := model.Demo()
	st.Tunnels[0].Enabled = false
	var exit model.Node
	for _, n := range st.Nodes {
		if n.ID == "exit-eu" {
			exit = n
		}
	}
	addrs := Addrs(st, exit)
	if len(addrs) != 1 || addrs[0] != "eu.example.com:22" {
		t.Errorf("без туннеля ожидался только прямой адрес, получено %v", addrs)
	}
}

func TestAddrsHonoursSSHPort(t *testing.T) {
	st := model.Demo()
	st.Nodes[1].SSHAddr = "eu.example.com:2222"
	addrs := Addrs(st, st.Nodes[1])
	if addrs[0] != "10.77.1.2:2222" {
		t.Errorf("порт SSH не подхвачен: %v", addrs)
	}
}

func TestProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-test\r\n")) // без баннера пробер считает хост мёртвым
			c.Close()
		}
	}()
	lat, ok := Probe(ln.Addr().String(), time.Second)
	if !ok {
		t.Fatal("живой порт не определился")
	}
	if lat <= 0 {
		t.Errorf("задержка = %v", lat)
	}
	if _, ok := Probe("127.0.0.1:1", 300*time.Millisecond); ok {
		t.Error("закрытый порт определился как живой")
	}

	// порт открыт, но это не SSH — не живой
	web, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer web.Close()
	go func() {
		for {
			c, err := web.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			c.Close()
		}
	}()
	if _, ok := Probe(web.Addr().String(), time.Second); ok {
		t.Error("не-SSH сервис определился как живой SSH")
	}
}
