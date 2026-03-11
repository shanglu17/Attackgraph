# DO-356A Appendix D Example Extraction (Pages 173-188)

Source file: `E:\document\airness\standard\DO-356A_1B3PF31I_unlocked-173-188.pdf`

## 1) Example Context (D.2.1)

- System: Air Management System (AMS) update example.
- Core LRUs: Pressurization Controller and Temperature Controller.
- Update channels: GSE and Ethernet router connection.
- Key buses/interfaces: ARINC 664, Ethernet, CAN, optional USB.
- Safety-critical focus in example risk analysis: FC.3 (loss of cabin pressurization, catastrophic).

## 2) Security Perimeter Interfaces (D.2.2.2)

- SI.1 Physical interface to ARINC 664 switch
- SI.2 Logical interface to Avionic system
- SI.3 Logical interface to Bleed system
- SI.4 Physical interface to Maintenance GSE
- SI.5 Logical interface to Manufacturer network via GSE
- SI.6 Physical interface to Ethernet switch
- SI.7 Logical interface to Airline network
- SI.8 Logical interface to Manufacturer network
- SI.9 Physical USB connection (not used in operation)

## 3) Information Assets (Table D-2)

- IA.1 Field loadable software
- IA.2 Configuration files
- IA.3 Firmware
- IA.4 Controller storage (certificates, keys, downloaded software/firmware)
- IA.5 LRU storage (configuration, logging, health monitoring)
- IA.6 ARINC 664 data messages
- IA.7 CAN messages exchanged with GSE

## 4) Threat Conditions and Priority Focus (D.2.3.1)

- Threat condition set includes SI.3 integrity/availability/confidentiality related items (e.g., TC.5/TC.6/TC.8).
- Risk assessment prioritizes FC.3 catastrophic condition and related attack paths.

## 5) Threat Scenarios (Table D-5)

- TS.1: CAN interface direct attack path to pressurization controller storage.
- TS.2: Maintenance GSE + CAN path to pressurization controller storage.
- TS.3: Wireless bridge + Ethernet switch multi-stage path to pressurization controller storage.
- TS.4: IFE + Ethernet switch path to pressurization controller storage.

## 6) Security Requirements in Example (D.2.3.2.1)

- SR1: Pressurization Controller accepts Ethernet download only on-ground and engine-off.
- SR2: External connections via Wireless Bridge only on-ground and engine-off.
- SR3: AMS LRUs allow Ethernet/CAN data exchange only in maintenance mode.

## 7) System Mapping Applied in This Repo

- Seed dataset now uses this Appendix D scenario:
  - Asset graph includes AMS, controllers, SI interfaces, GSE/IFE/wireless bridge/networks, and IA data assets.
  - Threat points include TS.1 to TS.4 as attack entry points.
  - DO326A_Link table stores traceability records using `standard_id` values referencing Appendix D TS/SR items.
- Runtime path analysis can now be executed directly on this dataset using the DPS + heuristic engine.

