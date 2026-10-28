"""Check the publishable tree for accidentally included credentials/private context."""
from pathlib import Path
import re
root = Path(__file__).resolve().parents[1]
patterns = [r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', r'gh[pousr]_[A-Za-z0-9]{30,}', r'https://1drv\.ms/', r'/Users/robertibert/']
errors = []
for folder in ['crates', 'macos', 'scripts', 'installer', '.github', 'docs']:
    for p in (root/folder).rglob('*'):
        if p.is_file() and p.suffix in {'.rs', '.m', '.py', '.md', '.sh', '.ps1', '.wxs', '.yml', '.txt'}:
            if p.name == 'check-source.py':
                continue
            text = p.read_text()
            if any(re.search(pattern, text) for pattern in patterns):
                errors.append(str(p.relative_to(root)))
if errors:
    raise SystemExit('Review potential secrets/private context: ' + ', '.join(errors))
print('Publishable source scan passed (pattern scan, not a complete secret detector).')
