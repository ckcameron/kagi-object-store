// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron.
// Kagi CSI driver: controller provisions logical volumes through the Kagi API;
// node service attaches each volume over the local NBD frontend.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const driverName = "csi.kagi.io"

type driver struct {
	csi.UnimplementedIdentityServer
	csi.UnimplementedControllerServer
	csi.UnimplementedNodeServer
	mode, endpoint, nodeID, stateDir string
	http *http.Client
}

func (d *driver) api(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader *strings.Reader
	if body != nil {
		b, err := json.Marshal(body); if err != nil { return nil, err }
		reader = strings.NewReader(string(b))
	}
	var req *http.Request
	var err error
	if reader == nil { req, err = http.NewRequestWithContext(ctx, method, strings.TrimRight(d.endpoint, "/")+path, nil) } else {
		req, err = http.NewRequestWithContext(ctx, method, strings.TrimRight(d.endpoint, "/")+path, reader)
		req.Header.Set("Content-Type", "application/json")
	}
	if err != nil { return nil, err }
	return d.http.Do(req)
}
func readJSON(resp *http.Response, out any) error {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 { return fmt.Errorf("Kagi API returned %s", resp.Status) }
	return json.NewDecoder(resp.Body).Decode(out)
}
func (d *driver) GetPluginInfo(context.Context, *csi.GetPluginInfoRequest) (*csi.GetPluginInfoResponse, error) {
	return &csi.GetPluginInfoResponse{Name: driverName, VendorVersion: "0.1.0"}, nil
}
func (d *driver) GetPluginCapabilities(context.Context, *csi.GetPluginCapabilitiesRequest) (*csi.GetPluginCapabilitiesResponse, error) {
	if d.mode != "controller" { return &csi.GetPluginCapabilitiesResponse{}, nil }
	return &csi.GetPluginCapabilitiesResponse{Capabilities: []*csi.PluginCapability{{Type: &csi.PluginCapability_Service_{Service: &csi.PluginCapability_Service{Type: csi.PluginCapability_Service_CONTROLLER_SERVICE}}}}}, nil
}
func (d *driver) Probe(context.Context, *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	return &csi.ProbeResponse{Ready: wrapperspb.Bool(true)}, nil
}
func (d *driver) ControllerGetCapabilities(context.Context, *csi.ControllerGetCapabilitiesRequest) (*csi.ControllerGetCapabilitiesResponse, error) {
	return &csi.ControllerGetCapabilitiesResponse{Capabilities: []*csi.ControllerServiceCapability{
		{Type: &csi.ControllerServiceCapability_Rpc{Rpc: &csi.ControllerServiceCapability_RPC{Type: csi.ControllerServiceCapability_RPC_CREATE_DELETE_VOLUME}}},
		{Type: &csi.ControllerServiceCapability_Rpc{Rpc: &csi.ControllerServiceCapability_RPC{Type: csi.ControllerServiceCapability_RPC_PUBLISH_UNPUBLISH_VOLUME}}},
	}}, nil
}
func (d *driver) CreateVolume(ctx context.Context, req *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error) {
	if req.GetName() == "" || len(req.GetVolumeCapabilities()) == 0 { return nil, status.Error(codes.InvalidArgument, "name and at least one volume capability are required") }
	size := req.GetCapacityRange().GetRequiredBytes()
	if size <= 0 { size = 10 * 1024 * 1024 * 1024 }
	const extent = 4 * 1024 * 1024
	if size > int64(^uint64(0)>>1)-(extent-1) { return nil, status.Error(codes.InvalidArgument, "requested capacity is too large") }
	size = ((size + extent - 1) / extent) * extent
	listResp, err := d.api(ctx, http.MethodGet, "/v1/volumes", nil)
	if err != nil { return nil, status.Errorf(codes.Unavailable, "list existing volumes: %v", err) }
	var existing map[string]struct {
			ID string `json:"id"`
			Name string `json:"name"`
			Size int64 `json:"size_bytes"`
		}
	if err = readJSON(listResp, &existing); err == nil {
		for _, v := range existing {
			if v.Name == req.GetName() {
				if v.ID == "" { continue }
				if v.Size < size { return nil, status.Error(codes.AlreadyExists, "volume name exists with smaller capacity") }
				return &csi.CreateVolumeResponse{Volume: &csi.Volume{VolumeId:v.ID, CapacityBytes:v.Size, VolumeContext:map[string]string{"apiEndpoint":d.endpoint}}}, nil
			}
		}
	} else { return nil, status.Errorf(codes.Unavailable, "decode volume list: %v", err) }
	presentations := []string{"kubernetes", "nbd"}
	body := map[string]any{"name":req.GetName(),"size_bytes":size,"logical_block_bytes":4096,"extent_bytes":extent,"thin_provisioned":true,"presentations":presentations}
	resp, err := d.api(ctx, http.MethodPost, "/v1/volumes", body)
	if err != nil { return nil, status.Errorf(codes.Unavailable, "create Kagi volume: %v", err) }
	var result struct { Volume struct { ID string `json:"id"`; Size int64 `json:"size_bytes"` } `json:"volume"` }
	if err := readJSON(resp, &result); err != nil { return nil, status.Errorf(codes.Internal, "decode Kagi create response: %v", err) }
	if result.Volume.ID == "" { return nil, status.Error(codes.Internal, "Kagi API returned no volume ID") }
	return &csi.CreateVolumeResponse{Volume:&csi.Volume{VolumeId:result.Volume.ID,CapacityBytes:result.Volume.Size,VolumeContext:map[string]string{"apiEndpoint":d.endpoint}}},nil
}
func (d *driver) DeleteVolume(ctx context.Context, req *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error) {
	if req.GetVolumeId() == "" { return nil, status.Error(codes.InvalidArgument, "volume_id is required") }
	resp, err := d.api(ctx, http.MethodDelete, "/v1/volumes/"+req.GetVolumeId(), nil)
	if err != nil { return nil, status.Errorf(codes.Unavailable, "delete Kagi volume: %v", err) }
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK { return &csi.DeleteVolumeResponse{}, nil }
	if resp.StatusCode == http.StatusConflict { return nil, status.Error(codes.FailedPrecondition, "Kagi refuses to delete a volume with allocated extents; use reclaimPolicy Retain and explicitly reclaim data") }
	return nil, status.Errorf(codes.Internal, "Kagi API returned %s deleting volume", resp.Status)
}
func (d *driver) ControllerPublishVolume(_ context.Context, req *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error) {
	if req.GetVolumeId()=="" || req.GetNodeId()=="" { return nil,status.Error(codes.InvalidArgument,"volume_id and node_id are required") }
	return &csi.ControllerPublishVolumeResponse{PublishContext:map[string]string{"apiEndpoint":d.endpoint}},nil
}
func (d *driver) ControllerUnpublishVolume(context.Context,*csi.ControllerUnpublishVolumeRequest)(*csi.ControllerUnpublishVolumeResponse,error) {
	return &csi.ControllerUnpublishVolumeResponse{},nil
}
func (d *driver) ValidateVolumeCapabilities(_ context.Context, req *csi.ValidateVolumeCapabilitiesRequest)(*csi.ValidateVolumeCapabilitiesResponse,error) {
	if req.GetVolumeId()=="" || len(req.GetVolumeCapabilities())==0 { return nil,status.Error(codes.InvalidArgument,"volume_id and capabilities required") }
	return &csi.ValidateVolumeCapabilitiesResponse{Confirmed:&csi.ValidateVolumeCapabilitiesResponse_Confirmed{VolumeCapabilities:req.GetVolumeCapabilities(),VolumeContext:req.GetVolumeContext()}},nil
}
func (d *driver) NodeGetCapabilities(context.Context,*csi.NodeGetCapabilitiesRequest)(*csi.NodeGetCapabilitiesResponse,error) {
	return &csi.NodeGetCapabilitiesResponse{Capabilities:[]*csi.NodeServiceCapability{{Type:&csi.NodeServiceCapability_Rpc{Rpc:&csi.NodeServiceCapability_RPC{Type:csi.NodeServiceCapability_RPC_STAGE_UNSTAGE_VOLUME}}}}},nil
}
func (d *driver) NodeGetInfo(context.Context,*csi.NodeGetInfoRequest)(*csi.NodeGetInfoResponse,error) {
	if d.nodeID=="" { return nil,status.Error(codes.FailedPrecondition,"KAGI_NODE_ID is required") }
	return &csi.NodeGetInfoResponse{NodeId:d.nodeID,MaxVolumesPerNode:128},nil
}
type stageState struct { VolumeID, Device, Port, ServerPID string; Filesystem bool; StagePath string }
func safeID(id string) string {
	base:=strings.Map(func(r rune) rune { if r>='a'&&r<='z'||r>='A'&&r<='Z'||r>='0'&&r<='9'||r=='-'||r=='_' {return r}; return '_' },id)
	if len(base)>64 { base=base[:64] }
	sum:=sha256.Sum256([]byte(id))
	return base+"-"+hex.EncodeToString(sum[:6])
}
func contains(items []string, wanted string) bool { for _,item:=range items { if item==wanted{return true} }; return false }
func (d *driver) statePath(id string) string { return filepath.Join(d.stateDir,safeID(id)+".json") }
func (d *driver) loadState(id string)(stageState,error) {
	var s stageState; b,e:=os.ReadFile(d.statePath(id)); if e!=nil{return s,e}; e=json.Unmarshal(b,&s); return s,e
}
func (d *driver) saveState(s stageState) error {
	if err:=os.MkdirAll(d.stateDir,0700);err!=nil{return err}
	b,err:=json.MarshalIndent(s,"","  ");if err!=nil{return err}
	tmp:=d.statePath(s.VolumeID)+".tmp";if err=os.WriteFile(tmp,b,0600);err!=nil{return err};return os.Rename(tmp,d.statePath(s.VolumeID))
}
func serverAlive(s stageState) bool {
	pid,err:=strconv.Atoi(s.ServerPID);if err!=nil||pid<=1{return false}
	cmdline,err:=os.ReadFile(fmt.Sprintf("/proc/%d/cmdline",pid))
	if err!=nil||!strings.Contains(string(cmdline),"kagi-volume-nbd")||!strings.Contains(string(cmdline),s.VolumeID){return false}
	base:=filepath.Base(s.Device)
	if !strings.HasPrefix(base,"nbd"){return false}
	devicePID,err:=os.ReadFile(filepath.Join("/sys/block",base,"pid"))
	return err==nil&&strings.TrimSpace(string(devicePID))!="0"
}
func cleanupStaleState(ctx context.Context,d *driver,s stageState) {
	if s.Filesystem { _ = run(ctx,"umount",s.StagePath) }
	if s.Device!="" { _ = run(ctx,"nbd-client","-d",s.Device) }
	if pid,err:=strconv.Atoi(s.ServerPID);err==nil&&pid>1 {
		cmdline,readErr:=os.ReadFile(fmt.Sprintf("/proc/%d/cmdline",pid))
		if readErr==nil&&strings.Contains(string(cmdline),"kagi-volume-nbd")&&strings.Contains(string(cmdline),s.VolumeID) {
			if p,e:=os.FindProcess(pid);e==nil{_ = p.Kill()}
		}
	}
	_ = os.Remove(d.statePath(s.VolumeID))
}
func run(ctx context.Context, name string, args ...string) error {
	cmd:=exec.CommandContext(ctx,name,args...); out,err:=cmd.CombinedOutput()
	if err!=nil{return fmt.Errorf("%s %v: %w: %s",name,args,err,strings.TrimSpace(string(out)))}
	return nil
}
func freeNBD() string {
	for i:=0;i<128;i++ { p:=fmt.Sprintf("/dev/nbd%d",i); if _,err:=os.Stat(p);err==nil {
		pid,err:=os.ReadFile(fmt.Sprintf("/sys/block/nbd%d/pid",i))
		if err==nil && strings.TrimSpace(string(pid))=="0" { return p }
	} }
	return ""
}
func (d *driver) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest)(*csi.NodeStageVolumeResponse,error) {
	id,stage:=req.GetVolumeId(),req.GetStagingTargetPath()
	if id==""||stage=="" { return nil,status.Error(codes.InvalidArgument,"volume_id and staging_target_path required") }
	if old,err:=d.loadState(id);err==nil {
		if serverAlive(old) {
			if old.StagePath==stage { return &csi.NodeStageVolumeResponse{},nil }
			return nil,status.Error(codes.AlreadyExists,"volume already staged at a different path")
		}
		cleanupStaleState(ctx,d,old)
	} else if !errors.Is(err,os.ErrNotExist) {
		return nil,status.Errorf(codes.Internal,"read existing stage state: %v",err)
	}
	api:=req.GetVolumeContext()["apiEndpoint"];if api=="" {api=d.endpoint};if api=="" {return nil,status.Error(codes.FailedPrecondition,"volume context lacks apiEndpoint and KAGI_API_ENDPOINT is unset")}
	vresp,err:=d.api(ctx,http.MethodGet,"/v1/volumes/"+id,nil);if err!=nil{return nil,status.Errorf(codes.Unavailable,"get volume: %v",err)}
	var vol struct { Size uint64 `json:"size_bytes"`; Block uint32 `json:"logical_block_bytes"`; ReadOnly bool `json:"read_only"` }
	if err=readJSON(vresp,&vol);err!=nil{return nil,status.Errorf(codes.Internal,"decode volume: %v",err)}
	if vol.ReadOnly && !req.GetReadonly() { return nil,status.Error(codes.FailedPrecondition,"Kagi volume is read-only but the pod requested a writable stage") }
	if req.GetVolumeCapability()==nil{return nil,status.Error(codes.InvalidArgument,"volume_capability is required")}
	fs:=req.GetVolumeCapability().GetMount()!=nil
	mountOptions:=[]string{"defaults"}
	if fs {
		fsType:=strings.ToLower(req.GetVolumeCapability().GetMount().GetFsType())
		if fsType!="" && fsType!="ext4" { return nil,status.Errorf(codes.InvalidArgument,"filesystem type %q is unsupported; only ext4 is supported",fsType) }
		for _,flag:=range req.GetVolumeCapability().GetMount().GetMountFlags() {
			switch flag { case "noatime","nodiratime","nodev","nosuid","noexec","sync","dirsync","ro": mountOptions=append(mountOptions,flag); default: return nil,status.Errorf(codes.InvalidArgument,"unsupported mount flag %q",flag) }
		}
		if req.GetReadonly() && !contains(mountOptions,"ro") { mountOptions=append(mountOptions,"ro") }
	}
	if err=os.MkdirAll(stage,0750);err!=nil{return nil,status.Errorf(codes.Internal,"create staging directory: %v",err)}
	if err=os.MkdirAll(d.stateDir,0700);err!=nil{return nil,status.Errorf(codes.Internal,"create CSI state directory: %v",err)}
	_ = run(ctx,"modprobe","nbd","nbds_max=128") // The module may already be loaded; device availability is checked below.
	portListener,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{return nil,status.Errorf(codes.Internal,"reserve NBD port: %v",err)}
	port:=portListener.Addr().(*net.TCPAddr).Port;_ = portListener.Close()
	server:=exec.Command("/usr/local/bin/kagi-volume-nbd","--listen",fmt.Sprintf("127.0.0.1:%d",port),"--api",api,"--volume",id,"--initiator","k8s:"+d.nodeID)
	logFile,logErr:=os.OpenFile(filepath.Join(d.stateDir,safeID(id)+".log"),os.O_CREATE|os.O_APPEND|os.O_WRONLY,0600)
	if logErr==nil {server.Stdout=logFile;server.Stderr=logFile}
	if err=server.Start();err!=nil{if logFile!=nil{_ = logFile.Close()};return nil,status.Errorf(codes.Unavailable,"start NBD frontend: %v",err)}
	go func(){ _ = server.Wait(); if logFile!=nil { _ = logFile.Close() } }()
	ready:=false
	for i:=0;i<50;i++ { c,e:=net.DialTimeout("tcp",fmt.Sprintf("127.0.0.1:%d",port),100*time.Millisecond);if e==nil{c.Close();ready=true;break};time.Sleep(100*time.Millisecond) }
	if !ready { _=server.Process.Kill(); return nil,status.Error(codes.Unavailable,"NBD frontend did not become ready") }
	device:=""
	for i:=0;i<128;i++ {
		candidate:=fmt.Sprintf("/dev/nbd%d",i)
		if _,e:=os.Stat(candidate);e!=nil{continue}
		pid,e:=os.ReadFile(fmt.Sprintf("/sys/block/nbd%d/pid",i));if e!=nil||strings.TrimSpace(string(pid))!="0"{continue}
		if e=run(ctx,"nbd-client","-N","keyspace","127.0.0.1",strconv.Itoa(port),candidate,"-b",strconv.Itoa(int(vol.Block)));e==nil{device=candidate;break}
	}
	if device=="" { _=server.Process.Kill();return nil,status.Error(codes.ResourceExhausted,"no free NBD device; load the nbd kernel module and expose /dev/nbd* to the node plugin") }
	s:=stageState{VolumeID:id,Device:device,Port:strconv.Itoa(port),ServerPID:strconv.Itoa(server.Process.Pid),Filesystem:fs,StagePath:stage}
	if fs {
		blkid:=exec.CommandContext(ctx,"blkid","-p","-s","TYPE","-o","value",device)
		fsOutput,fsErr:=blkid.CombinedOutput()
		if fsErr!=nil {
			var exitErr *exec.ExitError
			if errors.As(fsErr,&exitErr) && exitErr.ExitCode()==2 {
				if err=run(ctx,"mkfs.ext4","-F",device);err!=nil{_ = run(ctx,"nbd-client","-d",device);_ = server.Process.Kill();return nil,status.Errorf(codes.Internal,"format new volume as ext4: %v",err)}
			} else {
				_ = run(ctx,"nbd-client","-d",device);_ = server.Process.Kill()
				return nil,status.Errorf(codes.Internal,"could not safely inspect existing filesystem; refusing to format volume: %v: %s",fsErr,strings.TrimSpace(string(fsOutput)))
			}
		} else if found:=strings.TrimSpace(string(fsOutput));found!="" && found!="ext4" {
			_ = run(ctx,"nbd-client","-d",device);_ = server.Process.Kill()
			return nil,status.Errorf(codes.FailedPrecondition,"volume already contains %q filesystem; only ext4 is supported",found)
		}
		if err=run(ctx,"mount","-o",strings.Join(mountOptions,","),device,stage);err!=nil{_ = run(ctx,"nbd-client","-d",device);_ = server.Process.Kill();return nil,status.Errorf(codes.Internal,"mount staged filesystem: %v",err)}
	}
	if err=d.saveState(s);err!=nil{
		if fs { _ = run(ctx,"umount",stage) }
		_ = run(ctx,"nbd-client","-d",device)
		_ = server.Process.Kill()
		return nil,status.Errorf(codes.Internal,"save staging state: %v",err)
	}
	return &csi.NodeStageVolumeResponse{},nil
}
func (d *driver) NodeUnstageVolume(ctx context.Context,req *csi.NodeUnstageVolumeRequest)(*csi.NodeUnstageVolumeResponse,error) {
	s,err:=d.loadState(req.GetVolumeId());if errors.Is(err,os.ErrNotExist){return &csi.NodeUnstageVolumeResponse{},nil};if err!=nil{return nil,status.Errorf(codes.Internal,"read stage state: %v",err)}
	if s.Filesystem {if err=run(ctx,"umount",s.StagePath);err!=nil{return nil,status.Errorf(codes.FailedPrecondition,"unmount staged filesystem: %v",err)}}
	if err=run(ctx,"nbd-client","-d",s.Device);err!=nil{return nil,status.Errorf(codes.Internal,"disconnect NBD device: %v",err)}
	if pid,e:=strconv.Atoi(s.ServerPID);e==nil {
		cmdline,readErr:=os.ReadFile(fmt.Sprintf("/proc/%d/cmdline",pid))
		// Protect against killing a reused PID after a driver/container restart.
		if readErr==nil && strings.Contains(string(cmdline),"kagi-volume-nbd") && strings.Contains(string(cmdline),s.VolumeID) {
			if p,e:=os.FindProcess(pid);e==nil{_ = p.Kill()}
		}
	}
	_ = os.Remove(d.statePath(s.VolumeID));return &csi.NodeUnstageVolumeResponse{},nil
}
func (d *driver) NodePublishVolume(ctx context.Context,req *csi.NodePublishVolumeRequest)(*csi.NodePublishVolumeResponse,error) {
	s,err:=d.loadState(req.GetVolumeId());if err!=nil{return nil,status.Errorf(codes.FailedPrecondition,"volume is not staged: %v",err)}
	target:=req.GetTargetPath();if target==""{return nil,status.Error(codes.InvalidArgument,"target_path required")}
	if err=os.MkdirAll(filepath.Dir(target),0750);err!=nil{return nil,status.Errorf(codes.Internal,"create target parent: %v",err)}
	fs:=req.GetVolumeCapability().GetMount()!=nil
	if fs {
		if err=os.MkdirAll(target,0750);err!=nil{return nil,status.Errorf(codes.Internal,"create mount target: %v",err)}
		flags:=uintptr(syscall.MS_BIND)
		if req.GetReadonly(){flags|=syscall.MS_RDONLY}
		if err=syscall.Mount(s.StagePath,target,"",flags,"");err!=nil{return nil,status.Errorf(codes.Internal,"bind mount staged filesystem: %v",err)}
		if req.GetReadonly() { if err=syscall.Mount("",target,"",syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY,"");err!=nil{_ = syscall.Unmount(target,0);return nil,status.Errorf(codes.Internal,"remount filesystem read-only: %v",err)} }
	} else {
		f,openErr:=os.OpenFile(target,os.O_CREATE,0600);if openErr!=nil{return nil,status.Errorf(codes.Internal,"create block target: %v",openErr)};_ = f.Close()
		flags:=uintptr(syscall.MS_BIND)
		if req.GetReadonly(){flags|=syscall.MS_RDONLY}
		if err=syscall.Mount(s.Device,target,"",flags,"");err!=nil{return nil,status.Errorf(codes.Internal,"bind mount block device: %v",err)}
		if req.GetReadonly() { if err=syscall.Mount("",target,"",syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY,"");err!=nil{_ = syscall.Unmount(target,0);return nil,status.Errorf(codes.Internal,"remount block device read-only: %v",err)} }
	}
	return &csi.NodePublishVolumeResponse{},nil
}
func (d *driver) NodeUnpublishVolume(ctx context.Context,req *csi.NodeUnpublishVolumeRequest)(*csi.NodeUnpublishVolumeResponse,error) {
	if req.GetTargetPath()==""{return nil,status.Error(codes.InvalidArgument,"target_path required")}
	if err:=run(ctx,"umount",req.GetTargetPath());err!=nil&&!strings.Contains(err.Error(),"not mounted"){return nil,status.Errorf(codes.Internal,"unmount target: %v",err)}
	_ = os.Remove(req.GetTargetPath());return &csi.NodeUnpublishVolumeResponse{},nil
}
func (d *driver) NodeGetVolumeStats(ctx context.Context,req *csi.NodeGetVolumeStatsRequest)(*csi.NodeGetVolumeStatsResponse,error) {
	s,err:=d.loadState(req.GetVolumeId());if err!=nil{return nil,status.Error(codes.NotFound,"volume is not staged")}
	if !s.Filesystem { return nil,status.Error(codes.Unimplemented,"volume statistics are available only for filesystem-mode volumes") }
	var st syscall.Statfs_t
	path:=s.StagePath
	if err=syscall.Statfs(path,&st);err!=nil{return nil,status.Errorf(codes.Internal,"stat volume: %v",err)}
	return &csi.NodeGetVolumeStatsResponse{Usage:[]*csi.VolumeUsage{{Unit:csi.VolumeUsage_BYTES,Total:int64(st.Blocks)*int64(st.Bsize),Used:int64(st.Blocks-st.Bfree)*int64(st.Bsize)},{Unit:csi.VolumeUsage_INODES,Total:int64(st.Files),Used:int64(st.Files-st.Ffree)}}},nil
}
func (d *driver) serve() error {
	if d.mode!="controller"&&d.mode!="node"{return fmt.Errorf("mode must be controller or node")}
	if d.mode=="node"&&d.nodeID==""{return fmt.Errorf("KAGI_NODE_ID required for node mode")}
	socket:=os.Getenv("CSI_ENDPOINT");if socket==""{socket="unix:///csi/csi.sock"}
	socket=strings.TrimPrefix(socket,"unix://")
	if err:=os.MkdirAll(filepath.Dir(socket),0750);err!=nil{return err}
	_ = os.Remove(socket)
	l,err:=net.Listen("unix",socket);if err!=nil{return err}
	if err=os.Chmod(socket,0660);err!=nil{return err}
	s:=grpc.NewServer()
	csi.RegisterIdentityServer(s,d)
	if d.mode=="controller"{csi.RegisterControllerServer(s,d)}else{csi.RegisterNodeServer(s,d)}
	return s.Serve(l)
}
func main() {
	mode:=os.Getenv("KAGI_CSI_MODE")
	endpoint:=os.Getenv("KAGI_API_ENDPOINT")
	d:=&driver{mode:mode,endpoint:endpoint,nodeID:os.Getenv("KAGI_NODE_ID"),stateDir:os.Getenv("KAGI_CSI_STATE_DIR"),http:&http.Client{Timeout:30*time.Second}}
	if d.stateDir==""{d.stateDir="/var/lib/kagi-csi"}
	if err:=d.serve();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
