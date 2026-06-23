import re
import sys

subdomains = []
with open('/work/subs_input.txt') as f:
    for line in f:
        line = line.strip()
        if line:
            subdomains.append(line)

results = set()

ENV_WORDS = {'stg', 'dev', 'qa', 'prod', 'test', 'stage', 'staging', 'lab', 'eng', 'npe', 'uat', 'int', 'ext'}
ALL_ENVS = ['dev', 'stg', 'stage', 'staging', 'test', 'qa', 'prod', 'int', 'ext', 'lab', 'eng', 'uat', 'npe']

# Only use a small set of meaningful prefixes, not all env words
MEANINGFUL_PREFIXES = ['dev', 'stg', 'test', 'qa', 'stage', 'api', 'admin', 'internal', 'int', 'ext', 'uat', 'prod']

SWAPS = [
    ('stg', 'dev'), ('stg', 'prod'), ('stg', 'qa'), ('stg', 'test'), ('stg', 'stage'),
    ('dev', 'stg'), ('dev', 'prod'), ('dev', 'qa'), ('dev', 'test'),
    ('prod', 'stg'), ('prod', 'dev'), ('prod', 'qa'),
    ('qa', 'stg'), ('qa', 'dev'), ('qa', 'prod'),
    ('stage', 'staging'), ('staging', 'stage'), ('stage', 'stg'), ('staging', 'stg'),
    ('lab', 'eng'), ('eng', 'lab'), ('lab', 'stg'), ('lab', 'dev'), ('lab', 'prod'),
    ('qlab', 'plab'), ('plab', 'qlab'), ('qlab', 'ilab'), ('ilab', 'qlab'),
    ('plab', 'ilab'), ('ilab', 'plab'),
    ('us-east-1', 'us-west-2'), ('us-west-2', 'us-east-1'),
    ('int', 'ext'), ('ext', 'int'),
    ('npe', 'stg'), ('npe', 'dev'), ('npe', 'prod'),
    ('qat', 'dev'), ('qat', 'stg'),
    ('poc', 'dev'), ('poc', 'stg'),
    ('cnsdg', 'sdg'), ('sdg', 'cnsdg'), ('cnsdg1', 'sdg1'), ('sdg1', 'cnsdg1'),
    ('cnsdg2', 'sdg2'), ('sdg2', 'cnsdg2'),
    ('tfb', 'isp'), ('isp', 'tfb'),
    ('hmt', 'promos'), ('promos', 'hmt'),
    ('pel', 'sda'), ('sda', 'pel'),
    ('dab', 'kube'),  # Might find things
    ('dd-stg', 'dd-dev'), ('dd-stg', 'dd-prod'),
    ('prism', 'utopia'), ('utopia', 'prism'),
    ('kno', 'isp'),
]

NUM_DELTAS = [-1, 1, -2, 2, 3, -3, 4]

CITY_CODES = ['aro', 'atl', 'blt', 'bym', 'chi', 'chr', 'dal', 'det', 'elg', 'hon', 'hou',
              'irv', 'min', 'mir', 'nlv', 'nrc', 'nrt', 'nvl', 'orl', 'phi', 'plr',
              'rvs', 'syo', 'ttn', 'way', 'wsc', 'sea', 'nyc']

CNF_CODES = ['cnf01', 'cnf02', 'cnf03', 'cnf04', 'cnf05']
FUNC_CODES = ['tas', 'icf', 'scf', 'sre', 'bsf']
LAB_IDS = ['qlab01', 'qlab02', 'qlab03', 'qlab04', 'qlab05', 'qlab06', 'qlab07',
           'plab01', 'plab02', 'ilab01', 'ilab02', 'ilab03', 'pit']

for sub in subdomains:
    base = sub.replace('.t-mobile.com', '')
    parts = base.split('.')
    perms = set()

    # --- 1. Strip leading env prefix, add different env ---
    if parts[0] in ENV_WORDS:
        stripped = '.'.join(parts[1:])
        if stripped:
            perms.add(stripped)
            for env in ALL_ENVS:
                if env != parts[0]:
                    perms.add(f"{env}.{stripped}")
    else:
        # Add env prefix - but only 1-2, not all
        for pfx in ['dev', 'stg', 'prod', 'test']:
            perms.add(f"{pfx}.{base}")

    # --- 2. All word swaps ---
    for old, new in SWAPS:
        if old in base:
            perms.add(base.replace(old, new))

    # --- 3. Lab ID variations ---
    for lid in LAB_IDS:
        if lid in base:
            for other in LAB_IDS:
                if other != lid:
                    perms.add(base.replace(lid, other))

    # --- 4. Number variations ---
    nums = list(re.finditer(r'\d+', base))
    for m in nums:
        num_str = m.group(0)
        if len(num_str) > 4:
            continue
        num = int(num_str)
        for delta in NUM_DELTAS:
            new_num = num + delta
            if new_num < 0:
                continue
            new_str = str(new_num).zfill(len(num_str))
            perms.add(base[:m.start()] + new_str + base[m.end():])

    # --- 5. CNF swaps ---
    for cnf in CNF_CODES:
        if cnf in base:
            for other in CNF_CODES:
                if other != cnf:
                    perms.add(base.replace(cnf, other))

    # --- 6. Function code swaps ---
    for func in FUNC_CODES:
        if f'.{func}.' in base:
            for other in FUNC_CODES:
                if other != func:
                    perms.add(base.replace(f'.{func}.', f'.{other}.'))

    # --- 7. SGW city swaps ---
    sgw_m = re.search(r'sgw([a-z]+)', base)
    if sgw_m:
        city = sgw_m.group(1)
        for other in CITY_CODES:
            if other != city and len(other) == len(city):
                perms.add(base.replace(f'sgw{city}', f'sgw{other}', 1))

    # --- 8. SIP/SSF/SIM/SKA family number variations ---
    for family in ['sip', 'ssf', 'sim', 'ska']:
        fm = re.search(rf'\b({family})(\d+)', base)
        if fm:
            num = int(fm.group(2))
            for delta in [-1, 1, -2, 2, 3]:
                new_num = num + delta
                if new_num >= 0:
                    perms.add(base.replace(f'{fm.group(1)}{fm.group(2)}', f'{fm.group(1)}{new_num}'))

    # --- 9. Remove env/lab segments from middle ---
    if len(parts) >= 3:
        filtered = [p for p in parts if p not in ENV_WORDS and p not in LAB_IDS]
        if filtered and len(filtered) < len(parts):
            perms.add('.'.join(filtered))

    # --- 10. Remove trailing kubec/ccp/platform segments ---
    if parts[-1] in ('kube', 'ccp', 'digital', 'sipgeo', 'geo'):
        stripped_base = '.'.join(parts[:-1])
        if stripped_base:
            perms.add(stripped_base)
            # Also swap platform
            for plat in ['kube', 'ccp', 'digital', 'cloud']:
                if plat != parts[-1]:
                    perms.add('.'.join(parts[:-1]) + '.' + plat)

    # --- 11. lab↔stg↔eng↔dev in ANY position ---
    for pos, part in enumerate(parts):
        if part in ENV_WORDS:
            for env in ENV_WORDS:
                if env != part:
                    new_parts = list(parts)
                    new_parts[pos] = env
                    perms.add('.'.join(new_parts))

    # --- 12. Specific service swaps ---
    if '.msg.' in base:
        for repl in ['api', 'svc', 'svc.msg', 'msg.svc']:
            perms.add(base.replace('.msg.', f'.{repl}.') if '.' in repl else base.replace('.msg.', f'.{repl}.'))
    if '.api.' in base:
        perms.add(base.replace('.api.', '.msg.'))

    # --- 13. stg01/stg02 variations ---
    for prefix in ['stg01', 'stg02']:
        if prefix in base:
            for other in ['stg01', 'stg02', 'stg03', 'stg04', 'stg05']:
                if other != prefix:
                    perms.add(base.replace(prefix, other))

    # --- 14. siteN variations ---
    for prefix in ['site1', 'site2', 'site3']:
        if prefix in base:
            for other in ['site1', 'site2', 'site3', 'site4', 'site5']:
                if other != prefix:
                    perms.add(base.replace(prefix, other))

    # --- 15. Suffix additions for very simple hosts ---
    if len(parts) == 1:
        for sfx in ['-dev', '-stg', '-test', '-qa', '-prod']:
            perms.add(f"{base}{sfx}")

    # --- 16. "www" and "api" prefix for very simple hosts ---
    if len(parts) <= 2:
        for word in ['www', 'api', 'portal', 'cdn', 'mail']:
            if parts[0] != word:
                perms.add(f"{word}.{base}")

    # --- 17. sipgeo geo permutations ---
    if '.sipgeo.' in base:
        perms.add(base.replace('.sipgeo.', '.sip.'))
        perms.add(base.replace('.sipgeo.', '.voip.'))
    if '.sip.' in base:
        perms.add(base.replace('.sip.', '.sipgeo.'))

    # --- Clean and score ---
    perms.discard(base)

    # Scoring: higher = more interesting for bug bounty
    def score(p):
        s = 0
        p_parts = p.split('.')

        # STRONGLY penalize trivial prefix-only changes
        base_minus_first = '.'.join(parts[1:]) if len(parts) > 1 else ''
        p_minus_first = '.'.join(p_parts[1:]) if len(p_parts) > 1 else ''
        if p_minus_first == base or p_minus_first == base_minus_first:
            s -= 50  # Heavy penalty for just adding/changing a prefix

        # Reward structural changes
        if len(p_parts) != len(parts):
            s += 20

        # Reward in-the-middle changes (environment swaps, lab swaps)
        for i, pp in enumerate(p_parts):
            if i > 0 and i < len(p_parts) - 1 and i < len(parts):
                if pp != parts[i] and pp in ENV_WORDS:
                    s += 15

        # Reward env word changes
        for env in ENV_WORDS:
            if f'.{env}.' in p and f'.{env}.' not in base:
                s += 12

        # Reward region changes
        if ('us-east' in p and 'us-west' in base) or ('us-west' in p and 'us-east' in base):
            s += 15

        # Reward lab ID changes
        for lid in LAB_IDS:
            if lid in p and lid not in base:
                s += 10
                break

        # Reward number variations
        if re.search(r'\d', p) and re.search(r'\d', base):
            base_nums = set(re.findall(r'\d+', base))
            p_nums = set(re.findall(r'\d+', p))
            if base_nums != p_nums:
                s += 8

        # Reward platform/infra changes
        for plat in ['kube', 'ccp', 'digital', 'sipgeo', 'geo']:
            if plat in p and plat not in base:
                s += 10

        # Reward segment removal (shorter = more likely root domain)
        if len(p) < len(base):
            s += 5

        # Penalize overly long permutations (cumulative prefixes)
        if len(p_parts) > len(parts) + 2:
            s -= 10

        return s

    perms_list = [(p, score(p)) for p in perms if p and '.' in p]
    perms_list.sort(key=lambda x: x[1], reverse=True)

    # Take top 8
    for p, sc in perms_list[:8]:
        results.add(p + '.t-mobile.com')

# Output
for r in sorted(results):
    print(r)

sys.stderr.write(f"Generated {len(results)} permutations from {len(subdomains)} input subdomains\n")
