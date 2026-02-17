package plugin

// Capabilities describes what a plugin provides (KEM scheme names and/or sign algorithm names).
type Capabilities struct {
	KEM  []string `json:"kem"`
	Sign []string `json:"sign"`
}
