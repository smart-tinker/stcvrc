package adapter_test

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

func TestPassRuleMarshalJSONUsesClashVergeCompatibleType(t *testing.T) {
	proxy := adapter.NewProxy(outbound.NewPassRule())
	if proxy.Type() != C.PassRule {
		t.Fatalf("internal type = %v, want %v", proxy.Type(), C.PassRule)
	}

	raw, err := json.Marshal(proxy)
	if err != nil {
		t.Fatalf("marshal proxy: %v", err)
	}

	var payload struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal proxy json: %v", err)
	}
	if payload.Type != "Pass" {
		t.Fatalf("json type = %q, want %q", payload.Type, "Pass")
	}
}
