# CVE-2014-6271
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
### Base score v3.1.
9.8
### Link with description
- https://www.first.org/cvss/v4-0/examples
- https://www.twingate.com/blog/tips/cve-2014-6271
- https://cybersecurity.att.com/blogs/labs-research/attackers-exploiting-shell-shock-cve-2014-6271-in-the-wild
- https://en.wikipedia.org/wiki/Shellshock_(software_bug)

### Description
Shellshock could enable an attacker to cause Bash to execute arbitrary commands and gain unauthorized access to the app.

### CVSSv4
#### Base metrics (from first.org link)
##### Exploitability
- Attack Vector (AV): Network
- Attack Complexity (AC): Low
- Attack Requirements (AT): None
- Privileges Required (PR): None
- User Interaction (UI): None
##### Vulnerable System Impact Metrics
- Confidentiality (VC): High
- Integrity (VI): High
- Availability (VA): High
#### Exploit maturity (E) - Attacked
#### Modified base metrics - not changed
#### Enviromental metrics
##### Security
- Confidentiality Requirements (CR): High
- Integrity Requirements (IR): High
- Availability Requirements (AR): High
#### Supplemental metrics:
- Safety (S): Negligible (mostly used to create DDoS and vulnerability scanning botnets)
- Automatable (AU): Yes (script from link can be used)
- Recovery (R): X (not defined)
- Value Density (V): Concentrated (full access to bash)
- Vulnerability Response Effort (RE): X (not defined)
- Provider Urgency (U): X (not defined) (But should be red (?))
### Base score v4.0.
9.3.




# CVE-2017-3066
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
### Base score v3.1.
9.8.
### Link with description
- https://nvd.nist.gov/vuln/detail/CVE-2017-3066
- https://medium.com/@lucideus/cve-2017-3066-adobe-coldfusion-blazeds-java-object-deserialisation-rce-lucideus-research-64f31197757e
- https://github.com/vulhub/vulhub/blob/master/coldfusion/CVE-2017-3066/README.md
### Description
Remote code execution vulnerability in Adobe Coldfusion caused by unsafe deserialisation of java objects.
### CVSSv4
#### Base metrics (from links)
##### Exploitability
- Attack Vector (AV): Network
- Attack Complexity (AC): Low
- Attack Requirements (AT): None
- Privileges Required (PR): None
- User Interaction (UI): None
##### Vulnerable System Impact Metrics
- Confidentiality (VC): High
- Integrity (VI): High
- Availability (VA): High
#### Exploit maturity (E) - POC
#### Modified base metrics - not changed
#### Enviromental metrics
##### Security
- Confidentiality Requirements (CR): H
- Integrity Requirements (IR): H
- Availability Requirements (AR): H
#### Supplemental metrics:
- Safety (S): Negligible (ColdFusion is used to create websites)
- Automatable (AU): Yes (example in github link)
- Recovery (R): X
- Value Density (V): Concentrated (remote code execution, we can get anything)
- Vulnerability Response Effort (RE): X
- Provider Urgency (U): X
### Base score v4.0.
8.9.



# CVE-2019-11043
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
### Base score v3.1.
9.8.
### Link with description
- https://nvd.nist.gov/vuln/detail/CVE-2019-11043
- https://github.com/kriskhub/CVE-2019-11043
- https://medium.com/@knownsec404team/php-fpm-remote-code-execution-vulnerability-cve-2019-11043-analysis-35fd605dd2dc
### Description
Remote code execution (php, nginx server)
### CVSSv4
#### Base metrics (from links)
##### Exploitability
- Attack Vector (AV): Network
- Attack Complexity (AC): Low
- Attack Requirements (AT): None
- Privileges Required (PR): None
- User Interaction (UI): None
##### Vulnerable System Impact Metrics
- Confidentiality (VC): High
- Integrity (VI): High
- Availability (VA): High
#### Exploit maturity (E) - POC
#### Modified base metrics - not changed
#### Enviromental metrics
##### Security
- Confidentiality Requirements (CR): High
- Integrity Requirements (IR): High
- Availability Requirements (AR): High
#### Supplemental metrics:
- Safety (S): Negligible (Tech used mostly for websites)
- Automatable (AU): Yes (Example in github link)
- Recovery (R): X
- Value Density (V): (remote code execution)
- Vulnerability Response Effort (RE): X
- Provider Urgency (U): X
### Base score v4.0.
8.9.




# CVE-2019-2729
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
### Base score v3.1.
9.8.
### Link with description
- https://nvd.nist.gov/vuln/detail/CVE-2019-2729
- https://rootedshell.medium.com/oracle-weblogic-server-deserialization-rce-bcab4d7d6eae
- https://github.com/ruthlezs/CVE-2019-2729-Exploit
- https://www.oracle.com/security-alerts/alert-cve-2019-2729.html
### Description
Remote code execution in Oracle WebLogic Server Web Services
### CVSSv4
#### Base metrics (from links)
##### Exploitability
- Attack Vector (AV): Network
- Attack Complexity (AC): Low
- Attack Requirements (AT): None
- Privileges Required (PR): None
- User Interaction (UI): None
##### Vulnerable System Impact Metrics
- Confidentiality (VC): High
- Integrity (VI): High
- Availability (VA): High
#### Exploit maturity (E) - POC
#### Modified base metrics - not changed
#### Enviromental metrics
##### Security
- Confidentiality Requirements (CR): High
- Integrity Requirements (IR): High
- Availability Requirements (AR): High
#### Supplemental metrics:
- Safety (S): Negligible (Tech for websites)
- Automatable (AU): Yes (Example on github link)
- Recovery (R): X
- Value Density (V): Concentratred (Remote code execution)
- Vulnerability Response Effort (RE): X
- Provider Urgency (U): X
### Base score v4.0.
8.9.




# CVE-2020-0796
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
### Base score v3.1.
10.0
### Link with description
- https://nvd.nist.gov/vuln/detail/CVE-2020-0796
- https://sekurak.pl/cve-2020-0796-krytyczna-podatnosc-w-smbv3-mozna-bez-uwierzytelnienia-wykonac-dowolny-kod-na-windowsach-wlasnie-dostepny-jest-patch/
- https://github.com/jamf/CVE-2020-0796-RCE-POC
- https://github.com/danigargu/CVE-2020-0796
### Description
Windows privilege escalation (from any level to highest)
### CVSSv4
#### Base metrics (from links)
##### Exploitability
- Attack Vector (AV): Network
- Attack Complexity (AC): Low
- Attack Requirements (AT): None
- Privileges Required (PR): None
- User Interaction (UI): None
##### Vulnerable System Impact Metrics
- Confidentiality (VC): High
- Integrity (VI): High
- Availability (VA): High
#### Exploit maturity (E) - Attacked
#### Modified base metrics - not changed
#### Enviromental metrics
##### Security
- Confidentiality Requirements (CR): High
- Integrity Requirements (IR): High
- Availability Requirements (AR): High
#### Supplemental metrics:
- Safety (S): Present (full windows access (and windows is used everywhere))
- Automatable (AU): Yes (examples in github links)
- Recovery (R): X
- Value Density (V): Concentrated (full access to system)
- Vulnerability Response Effort (RE): X
- Provider Urgency (U): X
### Base score v4.0.
10.0.




# CVE-2020-1147
## CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
### Base score v3.1.
7.8
## CVSSv4
### Threat metrics:
- Exploit Maturity (EM) - Proof-of-Concept (P); p-o-c code is available, but there are no reported attacks.
### Environmental Metrics:
This vulnerability allows for the attacker to execute code with the same rights as the user that was the victim of the attack. Based on this fact if the attacker targets the right users any loss of Confidentiality/Integrity/Availability could be catasrophic.
- Confidentiality Requirements (CR) - High (H).
- Integrity Requirements (IR) - High (H).
- Availability Requirements (AR) - High (H).
- Modified base metrics - Not Defined (X).
### Supplemental Metrics:
- Safety (S) - Present (P); as seen in before mentioned metrics the consequences do not fit the definition of negligible and are definitelly of a higher caliber.
- Automatable (AU) - Yes (Y); an attacker could make a script that would place the exploitative XML file on a server and they could automate it for different users in that server or different servers.
- Provider Urgency (U) - Amber; based on the exploitability assessment provided by Microsoft.
- Recovery (R) - Not Defined (X)*.
- Value Density (V) - Concentrated (C); in the case of attacks on users with apt rights.
- Vulnerability Response Effort (RE) - Not Defined (X)*.   
*Based on the available information I can not define those metrics. There were no recorded attacks so there is no information on recovery and response to exploitation of this vulnerability.
### Source:
https://nvd.nist.gov/vuln/detail/CVE-2020-1147




# CVE-2020-1472
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
### Base score v3.1.
5.5 -> 10.0
## CVSSv4
### Threat metrics:
- Exploit Maturity (EM) - Proof-of-Concept (P); p-o-c code is avaiable, but there are no reported attacks.
### Environmental Metrics:
Allows for attackers to bypass security constraints (gain the credentials of the admin) remotely. The structure of the domain does not matter as the exploit of this vulnerability bypasses security no matter what, but the adverse effects could be catasrophic.
- Confidentiality Requirements (CR) - High (H).
- Integrity Requirements (IR) - High (H).
- Availability Requirements (AR) - High (H).
- Modified base metrics - Not Defined (X).
### Supplemental Metrics:
- Safety (S) - Present (P); the attacker can do anything on the domain.
- Automatable (AU) - Yes (Y); the exploitative code can be run remotely to access any domain.
- Provider Urgency (U) - Not Defined (X); the Samba security team was unaware of his vulnerability before Microsoft published an announcement including a patch that fixed it.
- Recovery (R) - Not Defined (X)*.
- Value Density (V) - Concentrated (C); the attacker gains access to the whole domain.
- Vulnerability Response Effort (RE) - Not Defined (X)*.   
*Based on the available information I can not define those metrics. There were no recorded attacks so there is no information on recovery and response to exploitation of this vulnerability.
### Source:
https://nvd.nist.gov/vuln/detail/CVE-2020-1472



# CVE-2020-14750
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
### Base score v3.1.
9.8
## CVSSv4
### Threat metrics:
- Exploit Maturity (EM) - Proof-of-Concept (P); p-o-c code is avaiable, but there are no reported attacks.
### Environmental Metrics:
Related to the below vulnerability (CVE-2020-14882). It is basically the same thing.
- Confidentiality Requirements (CR) - High (H).
- Integrity Requirements (IR) - High (H).
- Availability Requirements (AR) - High (H).
- Modified base metrics - Not Defined (X).
### Supplemental Metrics:
- Safety (S) - Present (P); the server could be completely compromised leading to catastrophic outcomes.
- Automatable (AU) - Yes (Y); p-o-c code could be auotmated to target multiple servers.
- Provider Urgency (U) - Not Defined (X); Oracle never mentioned the urgency.
- Recovery (R) - Not Defined (X)*.
- Value Density (V) - Concentrated (C); the attacker gains access to the whole server.
- Vulnerability Response Effort (RE) - Not Defined (X)*.   
*Based on the available information I can not define those metrics. There were no recorded attacks so there is no information on recovery and response to exploitation of this vulnerability.
### Source:
https://nvd.nist.gov/vuln/detail/CVE-2020-14750





# CVE-2020-14882
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
### Base score v3.1.
9.8
## CVSSv4
### Threat metrics:
- Exploit Maturity (EM) - Proof-of-Concept (P); p-o-c code is avaiable, but there are no reported attacks.
### Environmental Metrics:
Attacker can remotely bypass security and gain admin privileges so they can completely compromise the server.
- Confidentiality Requirements (CR) - High (H).
- Integrity Requirements (IR) - High (H).
- Availability Requirements (AR) - High (H).
- Modified base metrics - Not Defined (X).
### Supplemental Metrics:
- Safety (S) - Present (P); the server could be completely compromised leading to catastrophic outcomes.
- Automatable (AU) - Yes (Y); p-o-c code could be auotmated to target multiple servers.
- Provider Urgency (U) - Not Defined (X); Oracle never mentioned the urgency.
- Recovery (R) - Not Defined (X)*.
- Value Density (V) - Concentrated (C); the attacker gains access to the whole server.
- Vulnerability Response Effort (RE) - Not Defined (X)*.   
*Based on the available information I can not define those metrics. There were no recorded attacks so there is no information on recovery and response to exploitation of this vulnerability.
### Source:
https://nvd.nist.gov/vuln/detail/CVE-2020-14882




# CVE-2020-16846
shell injections
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
## CVSSv4
### Threat metrics:
- Exploit Maturity (EM) - POC **
** - http://packetstormsecurity.com/files/160039/SaltStack-Salt-REST-API-Arbitrary-Command-Execution.html
### Environmental Metrics:
- Confidentiality Requirements (CR) - High(H); you can learn a lot of info just from the shell
- Integrity Requirements (IR) - High(H); lots of things can be deleted
- Availability Requirements (AR) - High(H); servers down
- Modified base metrics - Not Defined (X)
### Supplemental Metrics:
- Safety (S) - Negligible(N); access to the shell, might be on important servers; should not be critical
- Automatable (AU) - Yes(Y)
- Recovery (R) - Not Defined (X)*
- Value Density (V) - Concentrated(C); shell access
- Vulnerability Response Effort (RE) - Not Defined (X)*
- Provider Urgency - Amber
* - no proof of attack, we cannot realistically estimate what would happen
https://nvd.nist.gov/vuln/detail/CVE-2020-16846
# CVE-2021-27877
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
## CVSSv4
remote code execution
### Threat metrics:
- Exploit Maturity (EM) - POC, https://www.rapid7.com/db/modules/exploit/multi/veritas/beagent_sha_auth_rce/
### Environmental Metrics:
- Confidentiality Requirements (CR) - High (H) ^
- Integrity Requirements (IR) - High (H) ^
- Availability Requirements (AR) - High (H) ^
^ - this is the exploitation in which remote code execution can happen, it compromises everything, no guarantees remaining.
- Modified base metrics - Not Defined (X)
### Supplemental Metrics:
- Safety (S) - Present(P); this could be used to handle medical data; if compromised - catastrophic effects
- Automatable (AU) - Yes (Y), POC is an automated script
- Recovery (R) - Not Defined (X)*
- Value Density (V) - Concentrated (C); remote code execution
- Vulnerability Response Effort (RE) - Not Defined (X) *
- Provider Urgency (U) - Red they recognized the danger **
* - no proof of attack, we cannot realistically estimate what would happen
** - https://www.veritas.com/content/support/en_US/security/VTS21-001#issue1
additional links:
- https://www.cvedetails.com/cve/CVE-2021-27877/
- https://nvd.nist.gov/vuln/detail/CVE-2021-27877
- http://packetstormsecurity.com/files/168506/Veritas-Backup-Exec-Agent-Remote-Code-Execution.html
# CVE-2021-44228
This exploit is known as Log4Shell, also known as the Log4j vulnerability, is a remote code execution (RCE) vulnerability in some versions of the Apache Log4j 2 Java library. Log4Shell allows hackers to run virtually any code they want on affected systems, essentially granting them total control of apps and devices.
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
## CVSSv4
### Threat metrics:
- Exploit Maturity (EM) - Attacked (A); ex. ransomware group Conti ^
^ - https://www.ibm.com/topics/log4shell#:~:text=IBM-,What%20is%20Log4Shell%3F,control%20of%20apps%20and%20devices.
### Environmental Metrics:
- Confidentiality Requirements (CR) - High(H) **
- Integrity Requirements (IR) - High(H) **
- Availability Requirements (AR) - High(H) ***
- Modified base metrics - Not Defined (X).
** - major attacks started happening after the exploit and fix has been published, meaning that if a company did not fix it immediately, they were deemed not trustworthy
*** - remote code execution, servers may go down
### Supplemental Metrics:
- Safety (S) - Present (P); may lead to loss of life if attacked
- Automatable (AU) - Yes (Y); botnets have been automatically scanning for it
- Recovery (R) - Irrecoverable (I); was used for ransomware
- Value Density (V) - Concentrated(C); access to server
- Provider Urgency (U) - Red; got fixed very fast
- Vulnerability Response Effort (RE) - Moderate(M); you had to perform an update
Additional links:
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- https://cert-portal.siemens.com/productcert/pdf/ssa-714170.pdf
# CVE-2022-29464
remote code execution (WSO2)
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
## CVSSv4
### Threat metrics:
- Exploit Maturity (EM) - Attacked; "Trend reported active exploitation of CVE-2022-29464 by actors who used the vulnerability to install crypto miners and backdoors through Cobalt Strike." *
* - https://www.hackthebox.com/blog/cve-2022-29464-explained#mcetoc_1hv2blqlt6q
### Environmental Metrics:
- Confidentiality Requirements (CR) - High(H) ^
- Integrity Requirements (IR) - High(H) ^
- Availability Requirements (AR) - High(H) ^
^ - rce
- Modified base metrics - Not Defined (X).
### Supplemental Metrics:
- Safety (S) - Present(P); WSO2 Healthcare
- Automatable (AU) - Yes (Y); look at ***
- Provider Urgency (U) - Red
- Recovery (R) - Irrecovable(I)
- Value Density (V) - Concentrated (C)
- Vulnerability Response Effort (RE) - Moderate; several changes to config files
Additional links:
- https://nvd.nist.gov/vuln/detail/CVE-2022-29464
- https://www.broadcom.com/support/security-center/attacksignatures/detail?asid=33699
- https://github.com/hakivvi/CVE-2022-29464 ***

# CVE-2023-27350
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
### Base score v3.1.
9.8

### Link with description:
- https://nvd.nist.gov/vuln/detail/CVE-2023-27350

### CVSSv4
#### Threat metrics:
- Exploit Maturity(E): Attacked; attacks were reported, Proof-of-Concept code available

#### Environmental metrics:
Attacker can run malicious code on PaperCut Application Server. In worst case they can gain access to all of  the data and the entire system
- Confidentiality Requirements(CR): H
- Integrity Requirements(IR): H
- Availability Requirements(AR): H
- Modified base metrics: X (not defined)

#### Sumpelental Metrics:
- Safety(S): P; the attacker can do anything from the system 
- Automatable(AU): Y; the exploitative code can be run remotely and access any vulnerable target
- Recovery(R):I; attacker could make irrecoverable changes
- Value Density(V):C; attacker can gain access to the entire system
- Vulnerability Response Effort(RE):M; consumers needed to update the software
- Provider Urgency(U):R; PaperCut confirmed vulnerability as urgent

#### Base score
9.3


# CVE-2023-27532
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
### Base score v3.1.
7.5

### Link with description:
- https://nvd.nist.gov/vuln/detail/CVE-2023-27532

### CVSSv4
#### Threat metrics:
- Exploit Maturity(E): P; Proof-of-Concept code exist, no attacks reported

#### Environmental metrics:
Attacker could gain access to plaintext credentials
- Confidentiality Requirements(CR): H
- Integrity Requirements(IR): L
- Availability Requirements(AR): L
- Modified base metrics: X (not defined)

#### Sumpelental Metrics:
- Safety(S): P; as attacker can gain access to credentials they could also perform remote command execution and do anything having local system privileges on a remote server
- Automatable(AU): Y; the exploitative code can be run remotely to access credentials
- Recovery(R): X*
- Value Density(V):C; attacker could have gain to database with plaintext credentials and then use them to obtrain RCE on vulnerable device
- Vulnerability Response Effort(RE): X*
- Provider Urgency(U): A; Veeam published a patch right after getting P-o-C

*Based on the available information I can not define those metrics. There were no recorded attacks so there is no information on recovery and response to exploitation of this vulnerability.

#### Base score
7.6


# CVE-2023-4863
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
### Base score v3.1.
8.8

### Link with description:
- https://nvd.nist.gov/vuln/detail/CVE-2023-4863

### CVSSv4
#### Threat metrics:
- Exploit Maturity(E):A; Google marked vulnerability as exploited in the wild

#### Environmental metrics:
Attacker overflowing buffer memory could execute arbitrary code or cause DoS condition
- Confidentiality Requirements(CR):H
- Integrity Requirements(IR):H
- Availability Requirements(AR):H
- Modified base metrics:
    - User Interaction(UI): P; opening malicious WebP image by user could lead to exploit

#### Sumpelental Metrics:
- Safety(S): P; attacker could gain acces to victims device and run code
- Automatable(AU): Y; malicious image could be simply sent to user by email or downloaded by user from website
- Recovery(R): I; system could have suffer from DoS attack or irrecoverable lost data
- Value Density(V): C; attacker could gain access to device of anyone who opened WebP file
- Vulnerability Response Effort(RE): M; update of any app that use WebP image was required
- Provider Urgency(U): R; chromium stated that security severity is critical and vulnerability was urgently patches after the inital report

#### Base score
9.3


# CVE-2023-5217
## CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
### Base score v3.1.
8.8
### Link with description:
- https://nvd.nist.gov/vuln/detail/CVE-2023-5217

### CVSSv4
#### Threat metrics:
- Exploit Maturity(E):A; Google stated that exploit exists in the wild

#### Environmental metrics:
Attacker could execute arbitrary code on the target system
- Confidentiality Requirements(CR):H
- Integrity Requirements(IR):H
- Availability Requirements(AR):H
- Modified base metrics:
    - User Interaction(UI): P; opening malicious HTML page by user could lead to exploit

#### Sumpelental Metrics:
- Safety(S):P, attacker could gain access to the vulnerable system
- Automatable(AU):Y; attacker could gain remote access via crafted HTML page
- Recovery(R): I, attacker could gain access to the system
- Value Density(V): C; affected was everyone who eg.opened attacker HTML page on chrome
- Vulnerability Response Effort(RE): M; all software using libvpx needed to updated
- Provider Urgency(U):A; Chromium security severity: High

#### Base score
9.3
