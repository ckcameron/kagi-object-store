package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
)

func TestSafeID(t *testing.T) {
	got := safeID("../volume:01")
	if !strings.HasPrefix(got, "___volume_01-") || strings.ContainsAny(got, "/:") {
		t.Fatalf("safeID returned unsafe or unexpected value %q", got)
	}
}
func TestCreateVolumeIsIdempotentByName(t *testing.T) {
	created := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method+" "+r.URL.Path {
		case "GET /v1/volumes":
			w.Header().Set("Content-Type","application/json")
			_, _ = w.Write([]byte(`{"existing":{"id":"existing","name":"data","size_bytes":20971520}}`))
		case "POST /v1/volumes":
			created = true
			t.Fatal("idempotent create unexpectedly called POST")
		default: t.Fatalf("unexpected request %s %s",r.Method,r.URL.Path)
		}
	}))
	defer server.Close()
	d:=&driver{endpoint:server.URL,http:server.Client()}
	out,err:=d.CreateVolume(context.Background(),&csi.CreateVolumeRequest{Name:"data",CapacityRange:&csi.CapacityRange{RequiredBytes:10*1024*1024},VolumeCapabilities:[]*csi.VolumeCapability{{AccessType:&csi.VolumeCapability_Mount{Mount:&csi.VolumeCapability_MountVolume{FsType:"ext4"}},AccessMode:&csi.VolumeCapability_AccessMode{Mode:csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER}}}})
	if err!=nil{t.Fatal(err)}
	if created{t.Fatal("created duplicate volume")}
	if out.GetVolume().GetVolumeId()!="existing"{t.Fatalf("unexpected volume: %#v",out.GetVolume())}
}
