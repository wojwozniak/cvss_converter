from cvss import CVSS3, CVSS4
C = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
def score_converter(cvss_vector: CVSS3, **kwargs) -> CVSS4:
    # input: cvss vector 3.1, missing fields
    # we will read in the additional fields with the value null (TODO: change it)
    # DELETE: Scope (S)
    # STAYS: AV,AC, PR (?)   : confidential req, integrity req, availibility
    # ADD: AT, SC, SI,SA     : suplemental metric group
    # CONVERT: VC, VI, VA, UI : Exploit maturity, modified base metrics
    # 'AT:N' , 'SC:N'

    old_vector = cvss_vector.vector # extract the vector string from the form
    prop = old_vector.split('/') # get the properties
    new_vector = 'CVSS:4.0' + '/' + '/'.join(prop[1:3]) # start a vector with the CVSS:4.0
    i = 0
    for key, value in kwargs.items():
        if i == 0:
            new_vector = new_vector + '/' + ("{0}:{1}".format(key, value)) + '/' + '/'.join(prop[3:5])
        else:
            new_vector = new_vector + '/' + ("{0}:{1}".format(key, value))
        i=+1
    return CVSS4(new_vector).vector# .vector returns a string, we return an object
print(score_converter(C, AT='N',VC = 'N', VI = 'N',VA = 'N', SC = 'N', SI = 'N', SA='N'))
