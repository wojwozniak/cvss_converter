W zależności czy mamy vulnerable system mamy VC VI VA a jak mamy subsequent to SC SI SA I będziemy je tak samo przeliczać
VA based on Availability (values stay the same)
VC based on Confidentiality (values stay the same)
VI based on Integrity (values stay the same)
UI if N leave N, else change R to P since P is more malicious attack(or A based on Attack Vector(?))

Questions:

------
Exploitability Metrics:

Attack Vector (AV)
Description:
Values:
Change from 3.1:
Attack Complexity (AC)
Description:
Values:
Change from 3.1:

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

It came from Attack Complexity - that metric has been split into Attack Complexity and Attack Requirements
Similar to Low/High values there.


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
Impact metrics:
Confidentiality (VC/SC)
Description:
Values:
Change from 3.1:
Integrity (VI/SI)
Description:
Values:
Change from 3.1:
Availability (VA/SA)
Description:
Values:
Change from 3.1:
