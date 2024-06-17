from cvss import CVSS3, CVSS4
from itertools import islice
C = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')

def score_converter(cvss_vector: CVSS3, **kwargs) -> CVSS4:
    # We assume the cvss_vector from 3.1 will have the standard layout
    # input: cvss vector 3.1, missing fields
    # we will read in the additional fields with the value null (TODO: change it)
    # DELETE: Scope (S)
    # STAYS: AV,AC, PR (?)   : confidential req, integrity req, availibility
    # ADD: AT, SC, SI,SA     : suplemental metric group
    # CONVERT: VC, VI, VA, UI : Exploit maturity, modified base metrics
    # 'AT:N' , 'SC:N'

    old_vector = cvss_vector.vector # extract the vector string from the form
    dic_old_vect = dict(x.split(":") for x in old_vector.split("/")) # get the properties
    new_vector = 'CVSS:4.0' + '/' + '/'.join(key + ':' +  str(val) for key,val in list(dic_old_vect.items())[1:3])
    # start a vector with the CVSS:4.0
    if 'AT' in kwargs.keys():
        new_vector =  new_vector + '/' + ("{0}:{1}".format('AT', kwargs['AT']))
    else:
        # we calculate AT based on AC (see documentation.md)
        if dic_old_vect["AC"] == "L":
            new_vector =  new_vector + '/' + "AT:N"
        elif dic_old_vect["AC"] == "H":
            new_vector =  new_vector + '/' + "AT:P"
    new_vector +=  '/' + '/'.join(key + ':' +  str(val) for key,val in list(dic_old_vect.items())[3:4])
    if dic_old_vect["UI"] == "N":
        new_vector =  new_vector + '/' + "UI:" + str(dic_old_vect['UI'])
    else:
        new_vector =  new_vector + '/' + "UI:P"
    add = ["SC", "SI", "SA"]

    new_vector =  new_vector + '/' + "VC:" + str(dic_old_vect['C'])  + '/' + "VI:" + str(dic_old_vect['I'])  + '/' + "VA:" + str(dic_old_vect['A'])
    for key, val in kwargs.items():
        if key in add:
            new_vector += "/" + ("{0}:{1}".format(key, val))
            # hidden assumption: we assume the additional keys and values are in order
    return CVSS4(new_vector).vector# .vector returns a string, we return an object
# VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
print(score_converter(C,VC = 'N', VI = 'N',VA = 'N', SC = 'N', SI = 'N', SA='N'))
#x = score_converter(C,VC = 'N', VI = 'N',VA = 'N', SC = 'N', SI = 'N', SA='N')
#print(x.base_score)
