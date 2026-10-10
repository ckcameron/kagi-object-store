package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
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

func TestControllerPublishFencesAndUnpublishReleasesNode(t *testing.T) {
	var mu sync.Mutex
	registrations := map[string]uint64{}
	holder := ""
	var reservationKey uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/v1/volumes/vol-1/pr" {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodGet {
			state := map[string]any{"registrations": map[string]any{}, "reservation": nil}
			regs := state["registrations"].(map[string]any)
			for name, key := range registrations { regs[name] = map[string]uint64{"key":key} }
			if holder != "" { state["reservation"] = map[string]any{"holder":holder,"key":reservationKey,"reservation_type":"exclusive_access"} }
			_ = json.NewEncoder(w).Encode(state)
			return
		}
		var op struct {
			Action string `json:"action"`
			Initiator string `json:"initiator"`
			CurrentKey uint64 `json:"current_key"`
			NewKey uint64 `json:"new_key"`
			Key uint64 `json:"key"`
			ReservationType string `json:"reservation_type"`
		}
		if err:=json.NewDecoder(r.Body).Decode(&op);err!=nil{http.Error(w,err.Error(),400);return}
		switch op.Action {
		case "register":
			if registrations[op.Initiator] != op.CurrentKey { http.Error(w,"key mismatch",http.StatusConflict);return }
			if op.NewKey==0 { delete(registrations,op.Initiator) } else { registrations[op.Initiator]=op.NewKey }
		case "reserve":
			if registrations[op.Initiator] != op.Key || (holder!="" && holder!=op.Initiator) { http.Error(w,"reserved",http.StatusConflict);return }
			holder=op.Initiator;reservationKey=op.Key
		case "release":
			if holder!=op.Initiator||reservationKey!=op.Key { http.Error(w,"not reservation holder",http.StatusConflict);return }
			holder="";reservationKey=0
		default: http.Error(w,"unknown action",400);return
		}
		w.Header().Set("Content-Type","application/json")
		_,_=w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	d:=&driver{endpoint:server.URL,http:server.Client()}
	ctx:=context.Background()
	if _,err:=d.ControllerPublishVolume(ctx,&csi.ControllerPublishVolumeRequest{VolumeId:"vol-1",NodeId:"node-1"});err!=nil{t.Fatal(err)}
	mu.Lock()
	if holder!="k8s:node-1" {t.Fatalf("reservation holder=%q",holder)}
	mu.Unlock()
	if _,err:=d.ControllerUnpublishVolume(ctx,&csi.ControllerUnpublishVolumeRequest{VolumeId:"vol-1",NodeId:"node-1"});err!=nil{t.Fatal(err)}
	mu.Lock()
	defer mu.Unlock()
	if holder!=""||len(registrations)!=0 {t.Fatalf("reservation/registrations not released: holder=%q registrations=%v",holder,registrations)}
}
