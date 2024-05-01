from cvss import CVSS3, CVSS4

def score_converter(cvss_vector,*args):
    # input: cvss vector 3.1, missing fields
    # we will read in the additional fields with the value null (TODO: change it)
    # DELETE: Scope (S)
    # STAYS: AV,AC, PR (?)   : confidential req, integrity req, availibility
    # ADD: AR, SC, SI,SA     : suplemental metric group
    # CONVERT: VC, VI, VA, UI : Exploit maturity, modified base metrics
    # 'AR:N' , 'SC:N'
    properties = cvss_vector.split('/')
    new_vector = "CVSS:4.0/" + properties[1] + '/' + properties[2] + '/' + args[0] + '/' + properties[3] + '/' + properties[4]
    for x in args[1:]:
        new_vector = new_vector + '/' + x
    c = CVSS4(new_vector)
    print(c.base_score)
score_converter('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'AT:N', "VC:N", "VI:N", "VA:N","SC:N","SI:N", "SA:N")