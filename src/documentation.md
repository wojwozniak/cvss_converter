# Exploitability Metrics:

## Attack Vector (AV)

Description: This metric measures how a vulnerability can be exploited

Values:
- Network(N) - component is remotely explotable, possible attacks extends these listed below
-  Adjacent(A) - component can be manipulated from the same shared physical (eg. Bluetooth) or logical network(local IP subnet) or limited administrative domain (eg secure VPN)
-  Local(L) - component can be manipulated by read/write/execute capablitiies (eg. using keyboard, ssh, opening malicious files by user)
-  Physical(P) - requires attacker to phyically touch or manipulate component (eg attack via DMA)

Change from 3.1: None

## Attack Complexity (AC)

Description: This metric captures measurable actions that must be taken by the attacker to actively evade built-in security-enhancing conditions in order to exploit the component

Values:
- Low(L) - attacker doesn't need to take any target-sepcific acction to explott the vulnerability
- High(H) - attack will be only succesfull if attacker evades security-enhancing techniques, attacker need additional methods to bypass this security measures (eg attacker needs to perform additional attacks to obtain a secret)

Change from 3.1: None

<br/>

## Attack Requirements (AR)

### Description:

Prerequisite deployment and execution conditions or variables of the vulnerable system that enable the attack.

### Values:

- None (N) - can be executed under any / most instances of the vulnerability

- Present (P) - many options:
  - there are some prerequisites needed that are outside of attacker control
  - race condition
  - network injection
  - multiple attacks needed against single target

### Change from 3.1:

It came from Attack Complexity (so it is a new-old metric) - old AC has been split into AC and AR.
Values are similar to Low/High values from old AC.


## Privileges Required (PR)


### Description:

This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability. The Base Score is greatest if no privileges are required. The list of possible values is presented in Table 3.

### Values:
- None (N)
  - The attacker is unauthorized prior to the attack.
  - No access to settings or files of the vulnerable system is needed.

- Low (L)
  - The attacker requires basic user capabilities.
  - Can affect settings and files owned by a user.
  - Alternatively, access is limited to non-sensitive resources.

- High (H)
  - The attacker requires significant privileges.
  - Provides control over the vulnerable component.
  - Allows access to component-wide settings and files.


### Change from 3.1:

Basically no change - just small corrections in wording of documentation.

<br />

User Interaction (UI)
Description:
Values:
Change from 3.1:
# Impact metrics:
#### Distinction between vulnerable and subsequent system:
vulnerable system -> software application, operating system, module, driver, etc. (or possibly a hardware device)
subsequent system -> any of those examples but also includes human safety.
Confidentiality (VC/SC)
Description:
Values:
Change from 3.1:
## Integrity (VI/SI)
VS - vulnerable system
SS - subsequent system
### Description:
Impact to accuracy and trustworthiness of information -> it is impacted when an attacker modifies the data or rejects critical actions.
### Values:
- High(H) <-> complete loss of integrity or protection
- Low(L)  <-> possibility of modification but no serious impact
- None(N) <-> no loss (in VS) or no loss or all integrity constrainted to VS (in SS)
### Change from 3.1:
distinction between Vulnerable and Subsequent System compared to just Integrity metric in 3.1. Values + their meanings stay the same
## Availability (VA/SA)

### Description:
Impact to accessibility of information resources -> loss of networked services, attacks containging network bandwidth consumption, processor cycles, disc space
### Values:
- High(H) <-> complete loss of availability, attacker can deny access to resources of both systems. Direct, serious consequences
- Low(L)  <-> performance is reduced or there are interruptions in resource availability, no direct consequence
- None(N) <-> no impact (in VS) or no impact or all availability impact constrainted to VS (in SS)
### Change from 3.1:
distinction between Vulnerable and Subsequent System compared to just Integrity metric in 3.1. Values + their meanings stay the same
