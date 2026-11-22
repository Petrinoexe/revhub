package model

// Demo — пример состояния: хаб с REALITY-инбаундом, выходной EU, обратный
// WG-туннель, один клиент и два правила. Используется командой `revhub demo`
// и тестами, чтобы генераторы проверялись на связной модели.
func Demo() State {
	privA, pubA, _ := GenRealityKeys()
	wgFromPriv, wgFromPub, _ := GenWGKeys()
	wgToPriv, wgToPub, _ := GenWGKeys()

	st := State{
		Version: StateVersion,
		Nodes: []Node{
			{ID: "hub", Name: "Хаб (вход)", Role: "entry", PublicAddr: "hub.example.com:443"},
			{ID: "exit-eu", Name: "Выходной EU", Role: "exit", PublicAddr: "eu.example.com:51821"},
		},
		Inbounds: []Inbound{{
			ID: "in-hub", NodeID: "hub", Tag: "hub-reality", Name: "Клиенты на хабе",
			Kind: "vless", Listen: "0.0.0.0", Port: 443, Transport: "tcp", Security: "reality",
			SNI: "www.microsoft.com", Dest: "www.microsoft.com:443",
			PrivateKey: privA, PublicKey: pubA, ShortID: GenShortID(),
			Flow: "xtls-rprx-vision", Enabled: true,
		}},
		Tunnels: []Tunnel{{
			ID: "tun-eu", Name: "eu", Kind: TunnelWGReverse,
			FromNode: "hub", ToNode: "exit-eu", Enabled: true,
			Subnet: "10.77.1.0/30", ListenPort: 51820, Keepalive: 25,
			FromKeyPriv: wgFromPriv, FromKeyPub: wgFromPub,
			ToKeyPriv: wgToPriv, ToKeyPub: wgToPub,
			Mark: 100, EgressIface: "ens3", ForwardPolicy: true,
		}},
		Clients: []Client{{
			ID: "cl-1", Email: "alice@revhub", UUID: GenUUID(), Enabled: true,
			Inbounds: []string{"in-hub"}, SubToken: GenToken(), Flow: "xtls-rprx-vision",
		}},
		Routes: []Rule{
			{ID: "r-1", Name: "RU-домены напрямую", Enabled: true,
				Domain: []string{"geosite:category-ru"}, Outbound: TagDirect},
			{ID: "r-2", Name: "Всё остальное — в EU-выходной", Enabled: true,
				Outbound: "tun:eu"},
		},
	}
	st.Normalize()
	return st
}
