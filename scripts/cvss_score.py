"""CVSS v3 base score, FIRST specification section 8.1. Other versions unscored."""
import math
SOURCE='https://www.first.org/cvss/v3.1/specification-document#8-1-Base-Metrics'
def base_score(vector):
    if not isinstance(vector,str) or not vector.startswith(('CVSS:3.0/','CVSS:3.1/')):return None
    try:
        m=dict(p.split(':',1) for p in vector.split('/')[1:]);changed=m['S']=='C'
        av={'N':.85,'A':.62,'L':.55,'P':.2}[m['AV']];ac={'L':.77,'H':.44}[m['AC']]
        pr={'N':.85,'L':.68 if changed else .62,'H':.5 if changed else .27}[m['PR']];ui={'N':.85,'R':.62}[m['UI']]
        impact_weights={'H':.56,'L':.22,'N':0};isc=1-math.prod(1-impact_weights[m[k]] for k in ('C','I','A'))
        impact=7.52*(isc-.029)-3.25*(isc-.02)**15 if changed else 6.42*isc
        if impact<=0:return 0.0
        value=min((1.08 if changed else 1)*(impact+8.22*av*ac*pr*ui),10)
        return math.ceil(round(value,5)*10)/10
    except (ValueError,KeyError):return None
