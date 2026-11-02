"""Google Identity Services integration. Disabled until explicit owner config exists."""
import hashlib,hmac,json,secrets,time
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit
ROOT=Path(__file__).parent
SESSIONS={};CHALLENGES={};ATTEMPTS={}
def config():
    p=ROOT/'google-login.json'
    if not p.exists():return None
    c=json.loads(p.read_text())
    if not c.get('enabled'):return None
    origin=urlsplit(c['origin'])
    if origin.scheme!='https' and not (origin.scheme=='http' and origin.hostname=='localhost'):
        raise ValueError('Google login requires HTTPS or localhost testing')
    if not c.get('client_id','').endswith('.apps.googleusercontent.com'):raise ValueError('OAuth web client ID required')
    if c.get('owner_email')!='ibert@ibert.se':raise ValueError('Owner allowlist must be explicitly reviewed')
    return c
def cookies(handler):
    try:c=SimpleCookie();c.load(handler.headers.get('Cookie',''));return {k:v.value for k,v in c.items()}
    except Exception:return {}
def session(handler):
    sid=cookies(handler).get('atlas_session','');row=SESSIONS.get(hashlib.sha256(sid.encode()).hexdigest())
    return row if row and row['expires']>time.time() else None
def verify_claims(claims,nonce,c):
    if claims.get('email','').lower()!=c['owner_email'] or claims.get('email_verified') is not True:raise ValueError('Account not allowed')
    if claims.get('hd')!='ibert.se':raise ValueError('Google Workspace authority required for this owner')
    if not claims.get('sub') or not hmac.compare_digest(str(claims.get('nonce','')),nonce):raise ValueError('Invalid sign-in challenge')
    p=ROOT/'google-owner-sub.json'
    if p.exists() and json.loads(p.read_text()).get('sub')!=claims['sub']:raise ValueError('Google account identity changed; owner review required')
    return claims['sub']
def reply_page(h):
    c=config()
    if not c:
        page='<h1>Google sign-in setup pending</h1><p>Owner: ibert@ibert.se. Google Cloud web client registration and localhost/HTTPS origin configuration are required. Login is not active yet.</p><a href="/">Back to dashboard</a>'
    else:
        expected=urlsplit(c['origin']).netloc
        if h.headers.get('Host','').lower()!=expected.lower():
            if h.client_address[0] in ('127.0.0.1','::1','10.0.88.189'):
                h.send_response(302);h.send_header('Location',c['origin']+'/login');h.end_headers();return
            h.reply({'error':'Google login currently available on the Mac at localhost only. The planned HTTPS domain is not live yet.'},503);return
        # Official google-auth is required; missing verifier must never bypass auth.
        try:from google.oauth2 import id_token
        except ImportError:h.reply({'error':'Google verifier is not installed; sign-in unavailable'},503);return
        now=time.time()
        for k in list(CHALLENGES):
            if CHALLENGES[k]['expires']<now:del CHALLENGES[k]
        if len(CHALLENGES)>500:h.reply({'error':'Sign-in busy'},503);return
        key=secrets.token_urlsafe(32);nonce=secrets.token_urlsafe(32);CHALLENGES[key]={'nonce':nonce,'expires':now+300}
        page='''<h1>Atlas · sign in</h1><p>Only the approved owner account can access this dashboard.</p><div id="google-button"></div><p id="result"></p><script src="https://accounts.google.com/gsi/client" async defer></script><script>
window.onload=()=>{google.accounts.id.initialize({client_id:CLIENT,nonce:NONCE,callback:async r=>{const response=await fetch('/auth/google',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({credential:r.credential})});if(response.ok)location.replace('/');else document.getElementById('result').textContent='Sign-in rejected; check the approved account or retry.';}});google.accounts.id.renderButton(document.getElementById('google-button'),{theme:'outline',size:'large'});};</script>'''.replace('CLIENT',json.dumps(c['client_id'])).replace('NONCE',json.dumps(nonce))
        h.send_response(200);h.send_header('Content-Type','text/html; charset=utf-8');h.send_header('Cache-Control','no-store');h.send_header('Referrer-Policy','no-referrer-when-downgrade');h.send_header('Cross-Origin-Opener-Policy','same-origin-allow-popups');h.send_header('Set-Cookie','atlas_challenge='+key+'; HttpOnly; SameSite=Lax; Path=/; Max-Age=300'+('; Secure' if c['origin'].startswith('https:') else ''));h.end_headers();h.wfile.write(page.encode());return
    h.send_response(200);h.send_header('Content-Type','text/html; charset=utf-8');h.end_headers();h.wfile.write(page.encode())
def login(h):
    c=config()
    if not c:h.reply({'error':'Google login not configured'},503);return
    if h.headers.get('Origin')!=c['origin']:h.reply({'error':'Origin rejected'},403);return
    now=time.time();peer=h.client_address[0];ATTEMPTS[peer]=[t for t in ATTEMPTS.get(peer,[]) if now-t<60]
    if len(ATTEMPTS[peer])>=8:h.reply({'error':'Too many attempts'},429);return
    ATTEMPTS[peer].append(now)
    try:
        size=int(h.headers.get('Content-Length','0'))
        if not 0<size<=16384:raise ValueError('Invalid body')
        data=json.loads(h.rfile.read(size));challenge=CHALLENGES.pop(cookies(h).get('atlas_challenge',''),None)
        if not challenge or challenge['expires']<now:raise ValueError('Challenge expired')
        from google.oauth2 import id_token
        from google.auth.transport import requests
        claims=id_token.verify_oauth2_token(data['credential'],requests.Request(),c['client_id'])
        sub=verify_claims(claims,challenge['nonce'],c)
        p=ROOT/'google-owner-sub.json'
        if not p.exists():p.write_text(json.dumps({'sub':sub}));p.chmod(0o600)
        for k in list(SESSIONS):
            if SESSIONS[k]['expires']<now:del SESSIONS[k]
        if len(SESSIONS)>100:raise ValueError('Session limit')
        sid=secrets.token_urlsafe(32);SESSIONS[hashlib.sha256(sid.encode()).hexdigest()]={'sub':sub,'expires':now+3600}
        payload=b'{"ok":true}';h.send_response(200);h.send_header('Content-Type','application/json');h.send_header('Cache-Control','no-store');h.send_header('Set-Cookie','atlas_session='+sid+'; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600'+('; Secure' if c['origin'].startswith('https:') else ''));h.end_headers();h.wfile.write(payload)
    except Exception:h.reply({'error':'Sign-in rejected; no token logged'},403)
def authenticated(h):
    return not config() or session(h) is not None

def logout(h):
    c=config()
    if not c or h.headers.get('Origin')!=c['origin']:h.reply({'error':'Origin rejected'},403);return
    sid=cookies(h).get('atlas_session','');SESSIONS.pop(hashlib.sha256(sid.encode()).hexdigest(),None)
    h.send_response(200);h.send_header('Content-Type','application/json');h.send_header('Set-Cookie','atlas_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'+('; Secure' if c['origin'].startswith('https:') else ''));h.end_headers();h.wfile.write(b'{"ok":true}')
