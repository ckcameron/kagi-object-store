package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		var op map[string]json.RawMessage
		if err:=json.NewDecoder(r.Body).Decode(&op);err!=nil{http.Error(w,err.Error(),400);return}
		var action string
		var payload struct {
			Initiator string `json:"initiator"`
			CurrentKey uint64 `json:"current_key"`
			NewKey uint64 `json:"new_key"`
			Key uint64 `json:"key"`
			ReservationType string `json:"reservation_type"`
			APTPL bool `json:"aptpl"`
			IgnoreExisting bool `json:"ignore_existing"`
		}
		for name,raw:=range op { action=name; if err:=json.Unmarshal(raw,&payload);err!=nil{http.Error(w,err.Error(),400);return} }
		switch action {
		case "register":
			if registrations[payload.Initiator] != payload.CurrentKey { http.Error(w,"key mismatch",http.StatusConflict);return }
			if payload.NewKey==0 { delete(registrations,payload.Initiator) } else { registrations[payload.Initiator]=payload.NewKey }
		case "reserve":
			if registrations[payload.Initiator] != payload.Key || (holder!="" && holder!=payload.Initiator) || payload.ReservationType!="exclusive_access" { http.Error(w,"reserved or invalid reservation type",http.StatusConflict);return }
			holder=payload.Initiator;reservationKey=payload.Key
		case "release":
			if holder!=payload.Initiator||reservationKey!=payload.Key||payload.ReservationType!="exclusive_access" { http.Error(w,"not reservation holder",http.StatusConflict);return }
			holder="";reservationKey=0
		default: http.Error(w,"unknown Serde PR operation",400);return
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
	if _,err:=d.ControllerPublishVolume(ctx,&csi.ControllerPublishVolumeRequest{VolumeId:"vol-1",NodeId:"node-2"});err==nil {
		t.Fatal("second node unexpectedly acquired an exclusive-access reservation")
	}
	mu.Lock()
	if holder!="k8s:node-1" {t.Fatalf("failed competing attach changed holder to %q",holder)}
	if _,ok:=registrations["k8s:node-2"];ok {t.Fatal("failed competing attach left a stale registration")}
	mu.Unlock()
	if _,err:=d.ControllerUnpublishVolume(ctx,&csi.ControllerUnpublishVolumeRequest{VolumeId:"vol-1",NodeId:"node-1"});err!=nil{t.Fatal(err)}
	mu.Lock()
	defer mu.Unlock()
	if holder!=""||len(registrations)!=0 {t.Fatalf("reservation/registrations not released: holder=%q registrations=%v",holder,registrations)}
}

func TestAPIAtUsesProvidedEndpointForJSONRequests(t *testing.T) {
	var firstHit, secondHit bool
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHit = true
		http.Error(w, "wrong endpoint", http.StatusInternalServerError)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHit = true
		if r.Method != http.MethodPost || r.URL.Path != "/test" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		if body["value"] != "correct" {
			t.Errorf("unexpected body: %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer second.Close()
	d := &driver{endpoint: first.URL, http: second.Client()}
	resp, err := d.apiAt(context.Background(), second.URL, http.MethodPost, "/test", map[string]string{"value":"correct"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if firstHit || !secondHit {
		t.Fatalf("endpoint selection incorrect: firstHit=%v secondHit=%v", firstHit, secondHit)
	}
}

func TestCreateVolumeRejectsMultiNodeAccessAndImpossibleRoundedLimit(t *testing.T) {
	d := &driver{endpoint: "http://127.0.0.1:1", http: &http.Client{Timeout: time.Millisecond}}
	capability := func(mode csi.VolumeCapability_AccessMode_Mode) *csi.VolumeCapability {
		return &csi.VolumeCapability{
			AccessType: &csi.VolumeCapability_Block{Block: &csi.VolumeCapability_BlockVolume{}},
			AccessMode: &csi.VolumeCapability_AccessMode{Mode: mode},
		}
	}
	_, err := d.CreateVolume(context.Background(), &csi.CreateVolumeRequest{
		Name:"multi-node", VolumeCapabilities:[]*csi.VolumeCapability{capability(csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER)},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("multi-node mode should be rejected, got %v", err)
	}
	_, err = d.CreateVolume(context.Background(), &csi.CreateVolumeRequest{
		Name:"capacity-limit",
		CapacityRange:&csi.CapacityRange{RequiredBytes:1<<20, LimitBytes:2<<20},
		VolumeCapabilities:[]*csi.VolumeCapability{capability(csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER)},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("rounded capacity beyond limit should be rejected before API call, got %v", err)
	}
}

func TestNodeCapabilitiesAdvertiseOnlyImplementedStatsAndStage(t *testing.T) {
	d := &driver{}
	resp, err := d.NodeGetCapabilities(context.Background(), &csi.NodeGetCapabilitiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[csi.NodeServiceCapability_RPC_Type]bool{}
	for _, cap := range resp.GetCapabilities() {
		got[cap.GetRpc().GetType()] = true
	}
	if !got[csi.NodeServiceCapability_RPC_STAGE_UNSTAGE_VOLUME] || !got[csi.NodeServiceCapability_RPC_GET_VOLUME_STATS] {
		t.Fatalf("missing implemented node capabilities: %v", got)
	}
}
