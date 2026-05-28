package control

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestNewLpmMapClosesMapOnBatchUpdateFailure(t *testing.T) {
	ensureMemlock(t)

	template, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LPMTrie,
		Flags:      unix.BPF_F_NO_PREALLOC,
		MaxEntries: 1,
		KeySize:    20,
		ValueSize:  4,
	})
	if err != nil {
		t.Skipf("skipping LPM map close test: NewMap failed: %v", err)
	}
	defer template.Close()

	batchErr := errors.New("batch update failed")
	var created *ebpf.Map
	oldBatchUpdate := bpfMapBatchUpdate
	bpfMapBatchUpdate = func(m *ebpf.Map, keys interface{}, values interface{}, opts *ebpf.BatchOptions) (int, error) {
		created = m
		return 0, batchErr
	}
	t.Cleanup(func() {
		bpfMapBatchUpdate = oldBatchUpdate
		if created != nil {
			_ = created.Close()
		}
	})

	obj := &bpfObjects{}
	obj.UnusedLpmType = template
	m, err := obj.newLpmMap([]_bpfLpmKey{{PrefixLen: 128}}, []uint32{1})
	if m != nil {
		t.Fatal("newLpmMap returned a map on batch update failure")
	}
	if !errors.Is(err, batchErr) {
		t.Fatalf("newLpmMap error = %v, want batch error", err)
	}
	if created == nil {
		t.Fatal("batch update did not receive created map")
	}
	if fd := created.FD(); fd != -1 {
		t.Fatalf("created map fd = %d, want closed fd -1", fd)
	}
}
