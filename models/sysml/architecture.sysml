// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Kagi SysML v2 architecture model; validate with a compatible SysML v2 tool.
package KagiArchitecture {
    requirement def DurabilityTarget {
        doc /* The protection policy must satisfy the configured durability objective. */
        attribute targetLossProbability : Real;
    }
    part def Disk;
    part def Host { part disks : Disk[*]; }
    part def Rack { part hosts : Host[*]; }
    part def Site { part racks : Rack[*]; }
    part def RaftMetadataService;
    part def ObjectStorageService;
    part def NamespaceService;
    part def BlockVolumeService;
    part def SecurityService;
    part def MaintenanceService;
    part def KagiSystem {
        part topology : Site[*];
        part metadata : RaftMetadataService;
        part objects : ObjectStorageService;
        part namespaces : NamespaceService;
        part volumes : BlockVolumeService;
        part security : SecurityService;
        part maintenance : MaintenanceService;
    }
    requirement <REQ-ARCH-001> durability {
        doc /* Durability claims require kagi-config analysis, not model assertions alone. */
        subject system : KagiSystem;
        attribute targetLossProbability : Real;
    }
    requirement <REQ-ARCH-002> verificationTraceability {
        doc /* Requirements map to implementation and verification evidence. */
        subject system : KagiSystem;
    }
}
