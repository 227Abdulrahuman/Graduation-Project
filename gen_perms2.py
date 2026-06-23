import sys
import re
import random

random.seed(42)

subdomains = []
with open('/work/subs_input.txt') as f:
    for line in f:
        line = line.strip()
        if line:
            subdomains.append(line)

results = set()

# City codes used in sgw hosts
city_codes = ['aro', 'blt', 'bym', 'chi', 'chr', 'dal', 'det', 'elg', 'hon', 'hou',
              'irv', 'min', 'mir', 'nlv', 'nrc', 'nrt', 'nvl', 'orl', 'phi', 'plr',
              'rvs', 'syo', 'ttn', 'way', 'wsc']
# CNF codes used in sim/ssf/ska
cnf_codes = ['cnf01', 'cnf02', 'cnf03', 'cnf04']
# Function codes
func_codes = ['tas', 'icf', 'scf', 'sre']
# Lab IDs
lab_ids = ['qlab01', 'qlab02', 'qlab03', 'qlab04', 'qlab06', 'qlab07', 'plab01', 'ilab02', 'ilab03']
# Regions
regions = ['us-east-1', 'us-west-2']
# Env modifier words
env_words = ['stg', 'dev', 'qa', 'prod', 'test', 'stage', 'staging', 'lab', 'eng', 'npe', 'uat', 'int', 'ext']
# Common prefixes for simple hosts
common_prefixes = ['dev', 'stg', 'test', 'qa', 'stage', 'api', 'admin', 'internal', 'www', 'int', 'ext', 'uat']

for sub in subdomains:
    base = sub.replace('.t-mobile.com', '')
    parts = base.split('.')
    perms = set()

    # === Strategy 1: Environment prefix variations (more selective) ===
    # Only add env prefix to relatively simple subdomains (<= 3 segments)
    if len(parts) <= 3:
        for pfx in common_prefixes:
            if parts[0] != pfx:
                perms.add(f"{pfx}.{base}")

    # === Strategy 2: Strip leading env prefix ===
    if parts[0] in env_words:
        stripped = '.'.join(parts[1:])
        if stripped:
            perms.add(stripped)
            # Also replace with different env
            for env in env_words:
                if env != parts[0]:
                    perms.add(f"{env}.{stripped}")

    # === Strategy 3: Environment/lab swaps within the name ===
    for old, new in [
        ('stg', 'dev'), ('stg', 'prod'), ('stg', 'qa'),
        ('dev', 'stg'), ('dev', 'prod'), ('dev', 'qa'),
        ('stage', 'staging'), ('staging', 'stage'), ('stage', 'stg'), ('staging', 'stg'),
        ('lab', 'eng'), ('eng', 'lab'), ('lab', 'stg'), ('lab', 'prod'),
        ('qlab', 'plab'), ('plab', 'qlab'), ('qlab', 'ilab'), ('ilab', 'qlab'),
        ('plab', 'ilab'), ('ilab', 'plab'),
        ('prod', 'stg'), ('prod', 'dev'),
        ('qat', 'dev'), ('qat', 'stg'),
        ('npe', 'stg'), ('npe', 'dev'),
    ]:
        if old in base:
            perms.add(base.replace(old, new))

    # === Strategy 4: Lab ID variations ===
    for lab_id in lab_ids:
        for other_lab in lab_ids:
            if lab_id != other_lab and lab_id in base:
                perms.add(base.replace(lab_id, other_lab))

    # === Strategy 5: Region swaps ===
    if 'us-east-1' in base:
        perms.add(base.replace('us-east-1', 'us-west-2'))
    if 'us-west-2' in base:
        perms.add(base.replace('us-west-2', 'us-east-1'))

    # === Strategy 6: Number variations ===
    num_matches = list(re.finditer(r'\d+', base))
    for m in num_matches:
        num_str = m.group(1)
        num = int(num_str)
        for delta in [-1, 1, -2, 2, 3, -3]:
            new_num = num + delta
            if new_num < 0:
                continue
            new_str = str(new_num).zfill(len(num_str))
            perms.add(base[:m.start(1)] + new_str + base[m.end(1):])

    # === Strategy 7: CNF code swaps for sim/ssf/ska hosts ===
    for cnf in cnf_codes:
        if cnf in base:
            for other_cnf in cnf_codes:
                if other_cnf != cnf:
                    perms.add(base.replace(cnf, other_cnf))

    # === Strategy 8: Function code swaps ===
    for func in func_codes:
        if f'.{func}.' in base:
            for other_func in func_codes:
                if other_func != func:
                    perms.add(base.replace(f'.{func}.', f'.{other_func}.'))

    # === Strategy 9: SGW city code variations ===
    sgw_match = re.match(r'sgw([a-z]+)(\d+.*)', base.split('.')[0]) if parts else None
    if not sgw_match:
        # Try matching the first part more generally
        for part in parts:
            m = re.match(r'sgw([a-z]+)(\d+.*)', part)
            if m:
                city = m.group(1)
                rest = m.group(2)
                for other_city in city_codes:
                    if other_city != city and len(other_city) == len(city):
                        perms.add(base.replace(f'sgw{city}', f'sgw{other_city}', 1))
                break

    # === Strategy 10: SIP/SSF/SIM/SKA host number variations ===
    for prefix in ['sip', 'ssf', 'sim', 'ska']:
        pattern = re.compile(rf'\b({prefix})(\d+)\.')
        pm = pattern.search(base)
        if pm:
            num = int(pm.group(2))
            for delta in [-1, 1, -2, 2, 3]:
                new_num = num + delta
                if new_num >= 0:
                    perms.add(base.replace(f'{pm.group(1)}{pm.group(2)}', f'{pm.group(1)}{new_num}'))

    # === Strategy 11: qlab number variations ===
    qlab_match = re.search(r'qlab(\d+)', base)
    if qlab_match:
        num = int(qlab_match.group(1))
        for delta in [-1, 1, -2, 2, 3, -3]:
            new_num = num + delta
            if 1 <= new_num <= 15:
                perms.add(base.replace(f'qlab{num:02d}', f'qlab{new_num:02d}'))

    # === Strategy 12: Remove intermediate segments ===
    if len(parts) >= 3:
        # Remove env/lab segments
        new_parts = [p for p in parts if p not in env_words and p not in lab_ids and p != 'kube']
        if new_parts and len(new_parts) < len(parts):
            perms.add('.'.join(new_parts))

    # === Strategy 13: Specific T-Mobile patterns ===
    # stg01/stg02 variations
    for stg_num in ['01', '02', '03', '04']:
        if 'stg01' in base:
            perms.add(base.replace('stg01', f'stg{stg_num}'))
        if 'stg02' in base:
            perms.add(base.replace('stg02', f'stg{stg_num}'))

    # site1/site2/site3 variations
    for site_num in ['1', '2', '3', '4', '5']:
        for existing in ['site1', 'site2', 'site3']:
            if existing in base and f'site{site_num}' != existing:
                perms.add(base.replace(existing, f'site{site_num}'))

    # stage/staging prefix handling
    if parts[0] == 'stage':
        stripped = '.'.join(parts[1:])
        perms.add(stripped)
        perms.add(f'staging.{stripped}')
        perms.add(f'stg.{stripped}')
    if parts[0] == 'staging':
        stripped = '.'.join(parts[1:])
        perms.add(stripped)
        perms.add(f'stage.{stripped}')
        perms.add(f'stg.{stripped}')

    # === Strategy 14: Common suffix additions for simple hosts ===
    if len(parts) == 1:
        for sfx in ['-dev', '-stg', '-test', '-qa', '-prod', '-api', '-admin']:
            perms.add(f"{base}{sfx}")

    # === Strategy 15: sip geo lab/staging permutations ===
    if '.lab.' in base:
        perms.add(base.replace('.lab.', '.stg.'))
        perms.add(base.replace('.lab.', '.eng.'))
        perms.add(base.replace('.lab.', '.dev.'))
    if '.stg.' in base:
        perms.add(base.replace('.stg.', '.lab.'))
        perms.add(base.replace('.stg.', '.dev.'))

    # Limit to at most 12 per subdomain, then randomly pick 8
    perms.discard(base)
    perms_list = [p for p in perms if p and len(p) > 0]

    # Pick up to 8, prioritizing more structural changes
    # Sort: prefer permutations that change more than just a prefix
    def score(p):
        s = 0
        # Prefer changes in the middle (structural)
        if p.count('.') != base.count('.'):
            s += 10
        # Prefer changes that don't just add a prefix
        if not p.startswith(('dev.', 'stg.', 'test.', 'qa.', 'api.', 'admin.')):
            s += 5
        # Prefer regional/DC changes
        if 'us-east' in p or 'us-west' in p:
            s += 3
        # Prefer number changes
        if re.search(r'\d', p):
            s += 2
        return s

    perms_list.sort(key=score, reverse=True)
    selected = perms_list[:8]

    for p in selected:
        results.add(p + '.t-mobile.com')

# Output
for r in sorted(results):
    print(r)
