package outboundgroup

import (
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/singledo"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type urlTestProxy struct {
	C.Proxy
	name  string
	delay uint16
	alive bool
}

func (p *urlTestProxy) Name() string                { return p.name }
func (p *urlTestProxy) AliveForTestUrl(string) bool { return p.alive }
func (p *urlTestProxy) LastDelayForTestUrl(string) uint16 {
	if !p.alive {
		return ^uint16(0)
	}
	return p.delay
}

type urlTestProvider struct {
	P.ProxyProvider
	proxies []C.Proxy
	version uint32
}

func (p *urlTestProvider) Proxies() []C.Proxy { return p.proxies }
func (p *urlTestProvider) Version() uint32    { return p.version }
func (p *urlTestProvider) Touch()             {}

func newTestURLGroup(proxies []C.Proxy, tolerance uint16) (*URLTest, *urlTestProvider) {
	provider := &urlTestProvider{proxies: proxies, version: 1}
	return &URLTest{
		GroupBase:  NewGroupBase(GroupBaseOption{Providers: []P.ProxyProvider{provider}}),
		tolerance:  tolerance,
		fastSingle: singledo.NewSingle[C.Proxy](time.Second),
	}, provider
}

func TestURLTestTolerance(t *testing.T) {
	for _, currentFirst := range []bool{true, false} {
		for _, tc := range []struct {
			name          string
			current       uint16
			other         uint16
			tolerance     uint16
			switchToOther bool
		}{
			{"below", 250, 180, 150, false},
			{"equal", 330, 180, 150, false},
			{"above", 331, 180, 150, true},
			{"tie", 180, 180, 0, false},
			{"zero", 181, 180, 0, true},
		} {
			position := "second"
			if currentFirst {
				position = "first"
			}
			t.Run(position+"/"+tc.name, func(t *testing.T) {
				current := &urlTestProxy{name: "current", delay: tc.current, alive: true}
				other := &urlTestProxy{name: "other", delay: tc.other, alive: true}
				proxies := []C.Proxy{other, current}
				if currentFirst {
					proxies = []C.Proxy{current, other}
				}
				group, _ := newTestURLGroup(proxies, tc.tolerance)
				group.fastNode = current
				want := current
				if tc.switchToOther {
					want = other
				}
				if got := group.fast(false); got != want {
					t.Fatalf("got %s, want %s", got.Name(), want.Name())
				}
			})
		}
	}
}

func TestURLTestSelectionLifecycle(t *testing.T) {
	a := &urlTestProxy{name: "A", delay: 50, alive: true}
	b := &urlTestProxy{name: "B", delay: 300, alive: true}
	group, provider := newTestURLGroup([]C.Proxy{a, b}, 150)
	check := func(want C.Proxy) {
		t.Helper()
		group.fastSingle.Reset()
		if got := group.fast(true); got != want {
			t.Fatalf("got %s, want %s", got.Name(), want.Name())
		}
	}
	check(a)
	a.alive = false
	check(b)
	a.alive = true
	a.delay = 250
	b.delay = 180
	check(b)
	group.selected = "A"
	check(a)
	group.selected = ""
	provider.proxies = []C.Proxy{b}
	provider.version++
	check(b)
	check(b)
}
