package model

import (
	"strings"
	"testing"
)

func TestClientFlowMatchesTransportAndOverride(t *testing.T) {
	in := Inbound{Transport: "tcp", Security: "tls", Flow: "xtls-rprx-vision"}
	if got := in.ClientFlow(Client{}); got != "xtls-rprx-vision" {
		t.Fatalf("inherited flow = %q", got)
	}
	if got := in.ClientFlow(Client{Flow: "none"}); got != "" {
		t.Fatalf("explicitly disabled flow = %q", got)
	}
	in.Transport = "xhttp"
	if got := in.ClientFlow(Client{Flow: "xtls-rprx-vision"}); got != "" {
		t.Fatalf("incompatible transport flow = %q", got)
	}
}

func TestRouteRequiresInboundAndOutboundOnSameNode(t *testing.T) {
	st := Demo()
	st.Inbounds[0].NodeID = "exit-eu"
	st.Routes = []Rule{{ID: "custom", Enabled: true, Inbound: []string{"hub-reality"}, Outbound: "tun:eu"}}
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "инбаунд") {
		t.Fatalf("expected incompatible inbound error, got %v", err)
	}
	st.Inbounds[0].NodeID = "hub"
	if err := st.Validate(); err != nil {
		t.Fatal(err)
	}
}
