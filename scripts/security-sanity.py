#!/usr/bin/env python3
"""Fail-closed build audit. Record findings as data, never auto-approve exceptions."""
import argparse,datetime,hashlib,json,subprocess,sys
import importlib.util
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
from cvss_score import base_score, SOURCE as CVSS_SOURCE
def main():
    p=argparse.ArgumentParser();p.add_argument('--output',default='evidence/security/latest.json');a=p.parse_args()
    report={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'unverified','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'known_vulnerabilities':[]}
    try:
        version=subprocess.check_output(['cargo','audit','--version'],text=True).strip()
        if not version.startswith('cargo-audit') or version.split()[-1]!='0.22.2':raise RuntimeError('Install reviewed cargo-audit 0.22.2 with --locked')
        run=subprocess.run(['cargo','audit','--json','--deny','warnings'],cwd=ROOT,capture_output=True,text=True)
        audit=json.loads(run.stdout);report['tool']=version;report['database']=audit.get('database',{})
        for row in audit.get('vulnerabilities',{}).get('list',[]):
            adv=row['advisory'];pkg=row['package'];report['known_vulnerabilities'].append({'id':adv['id'],'package':pkg['name'],'version':pkg['version'],'title':adv['title'],'cvss_vector':adv.get('cvss'),'score':base_score(adv.get('cvss')),'score_source':CVSS_SOURCE,'score_status':'CVSS v3 base calculation; unsupported vectors unscored','source':'https://rustsec.org/advisories/'+adv['id']+'.html','status':'Open — build blocked','affected_scope':'Current audited lockfile; target reachability requires triage'})
        report['warnings']=audit.get('warnings',{});report['advisory_status']='passed' if run.returncode==0 else 'blocked'
        report['lockfile_sha256']=hashlib.sha256((ROOT/'Cargo.lock').read_bytes()).hexdigest()
        spec=importlib.util.spec_from_file_location('currency',ROOT/'scripts/dependency-currency.py');currency=importlib.util.module_from_spec(spec);spec.loader.exec_module(currency)
        report['dependency_currency']=currency.check()
        pending=[x for x in report['dependency_currency'] if x['status']!='current']
        scan=subprocess.run([sys.executable,str(ROOT/'scripts/check-source.py')],cwd=ROOT,capture_output=True,text=True)
        report['source_scan']='passed' if scan.returncode==0 else 'blocked'
        report['status']='passed' if run.returncode==0 and not pending and scan.returncode==0 else 'blocked'
        report['maintenance_review_required']=len(pending)
        report['known_vulnerabilities'].sort(key=lambda r:r['score'] if r['score'] is not None else -1,reverse=True)
    except Exception as e:
        report['status']='unverified';report['error']=str(e)[:500]
    out=ROOT/a.output;out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n')
    print('Security sanity: '+report['status']+'; '+str(len(report['known_vulnerabilities']))+' known vulnerability findings; '+str(out.relative_to(ROOT)))
    return 0 if report['status']=='passed' else 1
if __name__=='__main__':sys.exit(main())
