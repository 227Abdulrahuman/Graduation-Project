import re
import sys

subdomains = []
with open('/work/subs_input.txt') as f:
    for line in f:
        line = line.strip()
        if line:
            subdomains.append(line)

results = set()

# Environment/semantic words for permutation
ENV_WORDS = {'stg', 'dev', 'qa', 'prod', 'test', 'stage', 'staging', 'lab', 'eng', 'npe', 'uat', 'int', 'ext'}
ALL_ENVS = ['dev', 'stg', 'stage', 'staging', 'test', 'qa', 'prod', 'int', 'ext', 'lab', 'eng', 'uat', 'npe']
PREFIXES = ['dev', 'stg', 'test', 'qa', 'stage', 'api', 'admin', 'internal', 'www', 'int', 'ext', 'uat', 'prod']
COMMON_WORDS = ['api', 'admin', 'internal', 'www', 'cdn', 'mail', 'vpn', 'portal', 'status', 'monitor']

# Comprehensive swap table
SWAPS = [
    # env swaps
    ('stg', 'dev'), ('stg', 'prod'), ('stg', 'qa'), ('stg', 'test'), ('stg', 'stage'),
    ('dev', 'stg'), ('dev', 'prod'), ('dev', 'qa'), ('dev', 'test'),
    ('prod', 'stg'), ('prod', 'dev'), ('prod', 'qa'),
    ('qa', 'stg'), ('qa', 'dev'), ('qa', 'prod'),
    ('stage', 'staging'), ('staging', 'stage'), ('stage', 'stg'), ('staging', 'stg'),
    ('lab', 'eng'), ('eng', 'lab'), ('lab', 'stg'), ('lab', 'dev'), ('lab', 'prod'),
    # lab ID swaps
    ('qlab', 'plab'), ('plab', 'qlab'), ('qlab', 'ilab'), ('ilab', 'qlab'),
    ('plab', 'ilab'), ('ilab', 'plab'),
    # region swaps
    ('us-east-1', 'us-west-2'), ('us-west-2', 'us-east-1'),
    # other
    ('int', 'ext'), ('ext', 'int'),
    ('npe', 'stg'), ('npe', 'dev'), ('npe', 'prod'),
    ('qat', 'dev'), ('qat', 'stg'),
    ('poc', 'dev'), ('poc', 'stg'),
]

# Number increment variations
NUM_DELTAS = [-1, 1, -2, 2, 3, -3, 4, 5]

# City codes for sgw/network hosts
CITY_CODES = ['aro', 'atl', 'blt', 'bym', 'chi', 'chr', 'dal', 'det', 'elg', 'hon', 'hou',
              'irv', 'min', 'mir', 'nlv', 'nrc', 'nrt', 'nvl', 'orl', 'phi', 'plr',
              'rvs', 'syo', 'ttn', 'way', 'wsc', 'sea', 'nyc', 'lax', 'sfo', 'phx']

CNF_CODES = ['cnf01', 'cnf02', 'cnf03', 'cnf04', 'cnf05']
FUNC_CODES = ['tas', 'icf', 'scf', 'sre', 'bsf']

LAB_IDS = ['qlab01', 'qlab02', 'qlab03', 'qlab04', 'qlab05', 'qlab06', 'qlab07',
           'plab01', 'plab02', 'ilab01', 'ilab02', 'ilab03', 'pit']

for sub in subdomains:
    base = sub.replace('.t-mobile.com', '')
    parts = base.split('.')
    perms = set()

    # --- 1. Env prefix variations (always) ---
    for pfx in PREFIXES:
        if parts[0] != pfx:
            perms.add(f"{pfx}.{base}")

    # --- 2. Strip leading env prefix, add different env prefix ---
    if parts[0] in ENV_WORDS:
        stripped = '.'.join(parts[1:])
        if stripped:
            perms.add(stripped)  # bare version
            for env in ALL_ENVS:
                if env != parts[0]:
                    perms.add(f"{env}.{stripped}")

    # --- 3. All env/lab/region word swaps ---
    for old, new in SWAPS:
        if old in base:
            perms.add(base.replace(old, new))

    # --- 4. Lab ID variations (swap lab IDs) ---
    for lid in LAB_IDS:
        if lid in base:
            for other in LAB_IDS:
                if other != lid:
                    perms.add(base.replace(lid, other))

    # --- 5. Number increment/decrement variations ---
    for m in re.finditer(r'\d+', base):
        num_str = m.group(0)
        # Skip very large numbers (timestamps, etc)
        if len(num_str) > 4:
            continue
        num = int(num_str)
        for delta in NUM_DELTAS:
            new_num = num + delta
            if new_num < 0:
                continue
            new_str = str(new_num).zfill(len(num_str))
            perms.add(base[:m.start()] + new_str + base[m.end():])

    # --- 6. CNF code swaps (for sim/ssf/ska hosts) ---
    for cnf in CNF_CODES:
        if cnf in base:
            for other in CNF_CODES:
                if other != cnf:
                    perms.add(base.replace(cnf, other))

    # --- 7. Function code swaps ---
    for func in FUNC_CODES:
        if f'.{func}.' in base or base.startswith(f'{func}.'):
            for other in FUNC_CODES:
                if other != func:
                    perms.add(base.replace(f'.{func}.', f'.{other}.'))
                    if base.startswith(f'{func}.'):
                        perms.add(base.replace(f'{func}.', f'{other}.', 1))

    # --- 8. SGW city code variations ---
    sgw_m = re.search(r'sgw([a-z]+)', base)
    if sgw_m:
        city = sgw_m.group(1)
        for other in CITY_CODES:
            if other != city and len(other) == len(city):
                perms.add(base.replace(f'sgw{city}', f'sgw{other}', 1))

    # --- 9. SIP/SSF/SIM/SKA host family number variations ---
    for family in ['sip', 'ssf', 'sim', 'ska']:
        fm = re.search(rf'\b({family})(\d+)', base)
        if fm:
            num = int(fm.group(2))
            for delta in [-1, 1, -2, 2, 3, -3]:
                new_num = num + delta
                if new_num >= 0:
                    perms.add(base.replace(f'{fm.group(1)}{fm.group(2)}', f'{fm.group(1)}{new_num}'))

    # --- 10. Remove intermediate environment/lab segments ---
    if len(parts) >= 3:
        filtered = [p for p in parts if p not in ENV_WORDS and p not in LAB_IDS]
        if filtered and len(filtered) < len(parts):
            perms.add('.'.join(filtered))
        # Also try removing just the first env segment
        if parts[0] in ENV_WORDS:
            perms.add('.'.join(parts[1:]))

    # --- 11. Suffix additions for simpler hosts ---
    if len(parts) <= 2:
        for sfx in ['-dev', '-stg', '-test', '-qa', '-prod', '-api', '-admin', '-int']:
            perms.add(f"{base}{sfx}")

    # --- 12. Common word prefix additions for simple hosts ---
    if len(parts) <= 2:
        for word in COMMON_WORDS:
            if parts[0] != word:
                perms.add(f"{word}.{base}")

    # --- 13. SIP/SSF geo lab variations ---
    if '.lab.' in base:
        perms.add(base.replace('.lab.', '.stg.'))
        perms.add(base.replace('.lab.', '.eng.'))
        perms.add(base.replace('.lab.', '.dev.'))
    if '.stg.' in base:
        perms.add(base.replace('.stg.', '.lab.'))
        perms.add(base.replace('.stg.', '.dev.'))

    # --- 14. stg01/stg02 variations ---
    for prefix in ['stg01', 'stg02']:
        if prefix in base:
            for other in ['stg01', 'stg02', 'stg03', 'stg04', 'stg05']:
                if other != prefix:
                    perms.add(base.replace(prefix, other))

    # --- 15. siteN variations ---
    for prefix in ['site1', 'site2', 'site3']:
        if prefix in base:
            for other in ['site1', 'site2', 'site3', 'site4', 'site5']:
                if other != prefix:
                    perms.add(base.replace(prefix, other))

    # --- 16. Replace env in last segment ---
    if parts[-1] in ENV_WORDS:
        for env in ENV_WORDS:
            if env != parts[-1]:
                new_parts = parts[:-1] + [env]
                perms.add('.'.join(new_parts))

    # --- 17. Specific T-Mobile patterns ---
    # cnsdg ↔ sdg swaps
    for src, dst in [('cnsdg', 'sdg'), ('sdg', 'cnsdg'), ('cnsdg1', 'sdg1'), ('sdg1', 'cnsdg1'),
                      ('cnsdg2', 'sdg2'), ('sdg2', 'cnsdg2')]:
        if src in base:
            perms.add(base.replace(src, dst))

    # mms ↔ sms
    for src, dst in [('mms', 'sms'), ('sms', 'mms')]:
        if f'.{src}.' in base:
            perms.add(base.replace(f'.{src}.', f'.{dst}.'))

    # msg ↔ other
    if '.msg.' in base:
        perms.add(base.replace('.msg.', '.api.'))
    if '.api.' in base:
        perms.add(base.replace('.api.', '.msg.'))

    # kube removal for stg.*.kube patterns
    if base.endswith('.kube') and len(parts) >= 2:
        perms.add('.'.join(parts[:-1]))

    # tfb ↔ other service swaps
    if '.tfb.' in base:
        perms.add(base.replace('.tfb.', '.isp.'))
    if '.isp.' in base:
        perms.add(base.replace('.isp.', '.tfb.'))

    # hmt ↔ promos
    if '.hmt.' in base:
        perms.add(base.replace('.hmt.', '.promos.'))

    # --- Clean and limit ---
    perms.discard(base)  # remove original
    perms_list = [p for p in perms if p and len(p) > 0 and '.' in p]

    # Score and select best 8
    def score(p):
        s = 0
        # Prefer structural changes (different segment count)
        if p.count('.') != base.count('.'):
            s += 10
        # Prefer non-prefix-only changes
        if not any(p.startswith(f'{pfx}.') for pfx in PREFIXES if pfx in p.split('.')[0] and p.split('.')[0] == pfx and base.split('.')[0] != pfx):
            s += 5
        # Prefer regional changes
        if 'us-east' in p or 'us-west' in p:
            s += 3
        # Prefer number changes
        if re.search(r'\d', p) and re.search(r'\d', base):
            s += 3
        # Prefer env/lab changes in the middle
        for env in ENV_WORDS:
            if f'.{env}.' in p and f'.{env}.' not in base:
                s += 4
        # Prefer shorter permutations (less likely to be wild)
        if len(p) < len(base):
            s += 2
        return s

    perms_list.sort(key=score, reverse=True)
    selected = perms_list[:8]

    for p in selected:
        results.add(p + '.t-mobile.com')

# Output
for r in sorted(results):
    print(r)

# Stats to stderr
sys.stderr.write(f"Generated {len(results)} permutations from {len(subdomains)} input subdomains\n")
