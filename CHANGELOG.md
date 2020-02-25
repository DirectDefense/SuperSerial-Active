# Change Log

## [0.5.0.1] (2016-11-22)
### Fixed
- Extender: minor bugfix in NodeScannerCheck.java to prevent scan from failing with all payload types enabled.

## [0.5] (2016-11-21)
### Added
- Extender: Support for vulnerability detection using Burp Collaborator (HTTP only, HTTPS and DNS not yet supported)
- Extender: include parameter name in "Issue Detail" when payload is submitted via a paramter (ex. WebSphere)
- Extender: Support for including the ysoserial payload type in the detection command
- Extender: highlight index generation via InsertionPoint classes.
- Extender: Separate class specifically for generating ysoserial payloads (to be used by all Burp tools)
- Extender: Option in "Connection Settings" tab for Burp Collaborator or SuperSerial Node
- Extender: Warning of connection to outdated SuperSerial Node
- Extender: "Select All" and "Select None" buttons in "Scan Settings" tab for ysoserial payload types
- Node: Support for accepting the name of the ysoserial payload type via URL parameter (technique)

### Fixed
- Node: Resume capability now saves upload time, upload source, and ysoserial payload type name correctly.

### Changed
- Extender: Changed version number to 0.5
- Extender: Changed title of detected issue(s) to "Java Deserialization Remote Code Execution"
- Extender: Changed default detection commands to include the ysoserial payload type in the requests
- Extender: "Issue Remediation" section now includes links to actual remediation solutions.
- Node: Changed version number to 0.5

### Removed
- Extender: Single general ScanIssue class (SerializationRCEExploitIssue.java), replaced by general abstract parent class and specific sub-classes

## [0.4.0.1] (2016-11-11)
### Fixed
- Node: Standardized all message printouts

### Changed
- README.md: Updated ysoserial URL

## [0.4] (2016-7-27)
### Added
- Extender: Support for >=ysoserial-0.0.3
- Extender: Configuration checkboxes under "Scan Settings" to enable/disable ysoserial payload types
- Extender: Checking version of connected SuperSerial Node (via heartbeat request) and displaying in SuperSerial->"Node Connection Settings" tab
- Extender: Removal of generated context on Node (via DELETE request) after active scan where no vulnerability is identified
- Node: Include version information in responses to heartbeat requests
- Node: Output when context is removed (via DELETE request)
- Node: Token command line argument: use inputted token as authentication token
- Node: Resume capability: execute node and re-create contexts from previous executions by reading temporary files; enabled via --resume command line option
- Node: Help printout describing different command-line arguments

### Fixed
- Extender: Commands table in SuperSerial->"Scan Settings" tab can now be repopulated after all commands have been removed.
- Node: class imports in SuperSerialNodeHelper class (changed from * to specific classes)

### Changed
- Extender: Updated JSON for Java to version 20160212
- Node: Updated JSON for Java to version 20160212
- Node: Format of command-line arguments (--arg=val)
- Node: Message included in responses to heartbeat requests (South Park quote)
- Node: Filename format for temporary files storing uploaded files (SuperSerial-UF-[NODEPATH].tmp) and access entries (SuperSerial-AE-[NODEPATH].tmp)
- Node: Moved bytes-to-hex converstion method to SuperSerialNodeHelper class
- README.md: Updated Extender Description
- README.md: Updated Extender Overview
- README.md: Updated Extender Configuration/Usage (Node command-line arguments, loading ysoserial via Burp settings, enabling/disabling payload types, adding/editing commands)
- README.md: Updated Extender Dependencies
- README.md: Updated Extender Building Instructions
- CHANGELOG.md: Updated

### Removed
- Extender: Requirement to recompile ysoserial and package it with the Extender (Extender/ysoserial/GeneratePayload.java)
- Extender: ysoserial license (due to above) (Extender/licenses/YSOSERIAL-LICENSE.TXT)

## [0.3.1] (2016-5-3)
### Fixed
- Node: Uploaded file/access entries now saved to correct directory on *nix systems.

### Changed
- CHANGELOG.md: Updated

## [0.3] (2016-3-10)
### Fixed
- Node: Standardized output of failed requests ("XXX request denied ...")

### Added
- Extender: Sub-tabs "Node Connection Settings" and "Scan Settings" Under SuperSerial tab.
- Extender: Setting (under SuperSerial->"Scan Settings") to automatically active scan all listed (by Burp) request parameters and JBoss insertion point when performing Active Scan.
- Extender: Allow users to add new or edit/delete existing operating system commands used during Active Scan (under SuperSerial->"Scan Settings").
- Extender: Allow users to re-arrange the order that operating system commands are testing during Active Scan.
- Node: Allow users to remove dynamically-generated contexts by sending DELETE request to context.

### Changed
- Extender: Moved all Node connection configuration settings to SuperSerial->"Node Connection Settings" sub-tab.
- Extender: Moved all Active Scan settings to SuperSerial->"Scan Settings" sub-tab.
- README.md: Updated build procedure
- CHANGELOG.md: Updated

## [0.2.1] (2016-1-25)
### Fixed
- Node: IP Address printout (now displaying the correct IPs when files/access entries are downloaded).

### Added
- Node: printouts now preceded by timestamps
- README.md: build procedure

### Changed
- Node: Uploaded files/access entries are now saved to [TMP]/SuperSerial directory rather than [TMP] directory.
- Node: Uploaded files/access entries are now written to files named "SuperSerial-[CONTEXT_PATH].tmp".
- README.md: Updated license
- CHANGELOG.md

## [0.2] (2015-12-30)
### Added
- CHANGELOG.md
- Extender: Support for active detection against Linux and Windows systems running WebSphere.
- Extender: Logic to create platform-based insertion points only under certain conditions, rather than automatically be default.

### Changed
- README.md: Include latest description.

## [0.1] (2015-12-09)
### Added
- Extender: Support for active detection of deserialization vulnerabilities against Linux and Windows systems running JBoss (Initial Release).
- Node: Standalone web server component used for vulnerability detection (Initial Release).
