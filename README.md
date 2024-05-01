# Funkcja konwertująca z CVSS 3.1 na CVSS 4.0

## Differences between CVSS 3.1 and CVSS 4:
### Retired base metric: SCOPE (S)
Vulnerable System Impact into Confidentiality (VC), Integrity (VI), Availability (VA)   
Subsequent System(s) Impact into Confidentiality (SC), Integrity (SI), Availability (SA)  
### Update to the base metric (UI):
CVSS v4.0 proposes the User Interaction (UI) metric to be more granular. CVSS v3.1 the User Interaction (UI) metric had values None(N) or Required(R). With CVSS v4.0 this metric now provides more granularity to the amount of interaction required as Passive (P) or Active (A).


Table of values (8.2):
https://www.first.org/cvss/v4.0/specification-document