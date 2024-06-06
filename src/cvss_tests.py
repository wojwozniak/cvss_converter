import pandas as pd
from cvss import CVSS3
from vector_converter import score_converter
df = pd.read_excel("src/data.xlsx")
df2 = df.loc[df['CVSS'] == 3.1]
vector_list = df2['CVSS vector'].tolist()
print(vector_list)
for x in vector_list:
    print(score_converter(CVSS3(x),VC = 'N', VI = 'N',VA = 'N', SC = 'H', SI = 'H', SA='N').base_score)
