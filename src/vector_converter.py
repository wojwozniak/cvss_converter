from cvss import CVSS3, CVSS4
C = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
def score_converter(cvss_vector: CVSS3, **kwargs) -> CVSS4:
    # input: cvss vector 3.1, missing fields
    # we will read in the additional fields with the value null (TODO: change it)
    # DELETE: Scope (S)
    # STAYS: AV,AC, PR (?)   : confidential req, integrity req, availibility
    # ADD: AR, SC, SI,SA     : suplemental metric group
    # CONVERT: VC, VI, VA, UI : Exploit maturity, modified base metrics
    # 'AR:N' , 'SC:N'
    #new_vector = 'CVSS:4.0/'
    #properties = cvss_vector.split('/')
    #new_vector = "CVSS:4.0/" + properties[1] + '/' + properties[2] + '/' + args[0] + '/' + properties[3] + '/' + properties[4]
    #for x in args[1:]:
    #    new_vector = new_vector + '/' + x
    #c = CVSS4(new_vector)
    #print(c.base_score)# return CVSS4(new_vector_string)
    #return CVSS4(new_vector)
    old_vector = cvss_vector.vector
    prop = old_vector.split('/')
    new_vector = 'CVSS:4.0' + '/' + '/'.join(prop[1:3])
    i = 0
    for key, value in kwargs.items():
        if i == 0:
            new_vector = new_vector + '/' + ("{0}:{1}".format(key, value)) + '/' + '/'.join(prop[3:5])
        else:
            new_vector = new_vector + '/' + ("{0}:{1}".format(key, value))
        i=+1
    return new_vector
print(score_converter(C, AT='N',VC = 'N', VI = 'N',VA = 'N', SC = 'N', SI = 'N', SA='N'))
