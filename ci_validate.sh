#!/usr/bin/env bash
# ci_validate.sh
# Meridian Financial Group — Local CI validation
# Mimics what the GitHub Actions pipeline runs.
# Usage: bash ci_validate.sh

set -e   # Exit on first failure
set -o pipefail

PASS=0
FAIL=0
SKIPPED=0

echo "================================"
echo "Meridian Network Automation CI"
echo "$(date)"
echo "================================"

run_check() {
    local name="$1"
    local cmd="$2"
    echo -n "  [$name] ... "
    if eval "$cmd" > /tmp/ci_output 2>&1; then
        echo "PASS"
        # Use pre-increment: ((++PASS)) returns the new value (≥1), exit code 0.
        # Post-increment ((PASS++)) returns the OLD value — if PASS was 0,
        # exit code is 1, which kills the script under set -e.
        ((++PASS))
    else
        echo "FAIL"
        cat /tmp/ci_output
        ((++FAIL))
    fi
}

echo ""
echo "--- Stage 1: Syntax Checks ---"

# Check all Python files for syntax errors.
# py_compile parses the file and raises SyntaxError if invalid —
# without actually executing any code.
for f in scripts/*.py sim/*.py; do
    [ -f "$f" ] || continue
    run_check "syntax:$(basename $f)" "python3 -m py_compile $f"
done

echo ""
echo "--- Stage 2: YAML Validation ---"

# yaml.safe_load() raises yaml.YAMLError on malformed YAML.
# We use safe_load (not load) to prevent code execution from untrusted YAML.
for f in baseline/*.yaml data/*.yaml inventory.yaml; do
    [ -f "$f" ] || continue
    run_check "yaml:$(basename $f)" "python3 -c \"import yaml; yaml.safe_load(open('$f'))\""
done

echo ""
echo "--- Stage 3: Policy Integrity Checks ---"

# Ensure security_policy.yaml contains the required keys
run_check "policy:required_keys" "python3 -c \"
import yaml
with open('baseline/security_policy.yaml') as f:
    p = yaml.safe_load(f)
assert 'required_config_lines' in p, 'Missing required_config_lines'
assert 'forbidden_config_lines' in p, 'Missing forbidden_config_lines'
assert len(p['required_config_lines']) > 0, 'required_config_lines is empty'
print('Policy keys OK')
\""

# Ensure no ACL has 'permit ip any any' in a required entry.
# This check prevents a misconfigured policy from creating a firewall hole.
run_check "policy:no_permit_any" "python3 -c \"
import yaml
with open('data/acl_policy.yaml') as f:
    policy = yaml.safe_load(f)
for acl in policy['access_lists']:
    if acl.get('blacklist'):
        continue
    for rule in acl['rules']:
        if rule['action'] == 'permit' and rule.get('source') == 'any' and rule.get('destination') == 'any' and rule['protocol'] == 'ip':
            raise AssertionError('SECURITY VIOLATION: permit ip any any found in ' + acl['name'])
print('ACL policy OK')
\""

echo ""
echo "--- Stage 4: Jinja2 Template Rendering ---"

# Render all ACLs from the policy — confirms template syntax is valid
# and the YAML data structure matches what the template expects.
run_check "template:acl_render" "python3 -c \"
from jinja2 import Environment, FileSystemLoader
import yaml
env = Environment(loader=FileSystemLoader('templates'))
t = env.get_template('cisco_acl.j2')
with open('data/acl_policy.yaml') as f:
    policy = yaml.safe_load(f)
for acl in policy['access_lists']:
    rendered = t.render(acl=acl, timestamp='TEST')
    assert acl['name'] in rendered, f'ACL name missing from rendered output'
print('All templates render OK')
\""

echo ""
echo "--- Stage 5: Secret Hygiene ---"

# Fail if any script contains a hardcoded password pattern.
# This catches the most common credential leak pattern:
#   password = "SomePlaintext"
# It won't catch all leaks (encrypted values, obfuscation) but catches accidents.
run_check "secrets:no_hardcoded_passwords" "python3 -c \"
import re, glob, sys
patterns = [
    r'password\s*=\s*[\"\\x27][^\"\\x27]{6,}',
    r'secret\s*=\s*[\"\\x27][^\"\\x27]{6,}',
]
issues = []
for path in glob.glob('scripts/*.py') + glob.glob('sim/*.py'):
    with open(path) as f:
        content = f.read()
    for pat in patterns:
        if re.search(pat, content, re.IGNORECASE):
            issues.append(f'{path}: possible hardcoded credential')
if issues:
    print('\n'.join(issues))
    sys.exit(1)
print('No hardcoded secrets found')
\""

echo ""
echo "================================"
echo "Results: PASS=$PASS  FAIL=$FAIL  SKIPPED=$SKIPPED"
echo "================================"

if [ "$FAIL" -gt 0 ]; then
    echo "CI FAILED — do not deploy"
    exit 1
else
    echo "CI PASSED — safe to deploy"
    exit 0
fi