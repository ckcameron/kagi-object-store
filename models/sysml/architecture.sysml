// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Kagi architecture model. CI syntax-checks this file with sysml2 0.3.1.
package KagiArchitecture {
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
    part def PlannerConstraints {
        attribute minimumHosts : Integer = 6;
        attribute minimumDisksPerHost : Integer = 6;
        attribute protectionScheme : String = "clay";
    }
    part def KagiSystem {
        part topology : Site[*];
        part metadata : RaftMetadataService;
        part objects : ObjectStorageService;
        part namespaces : NamespaceService;
        part volumes : BlockVolumeService;
        part security : SecurityService;
        part maintenance : MaintenanceService;
        part plannerConstraints : PlannerConstraints;
    }
    requirement <'REQ-ARCH-001'> durability {
        doc /* Durability estimates are produced by kagi-config; the model does not assert a loss probability. */
        subject system : KagiSystem;
    }
    requirement <'REQ-ARCH-002'> plannerConstraintsAreApplied {
        doc /* Planner constraints are validated and applied by the SysML adapter before kagi-config runs. */
        subject system : KagiSystem;
    }
    requirement <'REQ-ARCH-003'> verificationTraceability {
        doc /* Requirements map to implementation and automated verification evidence. */
        subject system : KagiSystem;
    }
}
