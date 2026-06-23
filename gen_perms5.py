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
PREFIXES = ['dev', 'stg', 'test', 'qa', 'stage', 'api', 'admin', 'internal', 'www', 'int', 'ext', 'uat', 'prod']

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
    ('dd-stg', 'dd-dev'), ('dd-stg', 'dd-prod'),
    ('prism', 'utopia'), ('utopia', 'prism'),
    ('cco', 'ccp'), ('sipgeo', 'sip'), ('mms', 'sms'), ('sms', 'mms'),
    ('npp', 'ppm'), ('ppm', 'npp'),
    ('dab', 'kno'),
    ('msg', 'api'),
]

NUM_DELTAS = [-1, 1, -2, 2, 3, -3, 4, 5]

CITY_CODES = ['aro', 'atl', 'blt', 'bym', 'chi', 'chr', 'dal', 'det', 'elg', 'hon', 'hou',
              'irv', 'min', 'mir', 'nlv', 'nrc', 'nrt', 'nvl', 'orl', 'phi', 'plr',
              'rvs', 'syo', 'ttn', 'way', 'wsc', 'sea', 'nyc', 'lax', 'sfo', 'phx']

CNF_CODES = ['cnf01', 'cnf02', 'cnf03', 'cnf04', 'cnf05']
FUNC_CODES = ['tas', 'icf', 'scf', 'sre', 'bsf']
LAB_IDS = ['qlab01', 'qlab02', 'qlab03', 'qlab04', 'qlab05', 'qlab06', 'qlab07',
           'plab01', 'plab02', 'ilab01', 'ilab02', 'ilab03', 'pit']

PLATFORMS = ['kube', 'ccp', 'digital', 'sipgeo', 'geo', 'cloud']

for sub in subdomains:
    base = sub.replace('.t-mobile.com', '')
    parts = base.split('.')
    perms = set()

    # --- 1. Strip and replace env prefix ---
    if parts[0] in ENV_WORDS:
        stripped = '.'.join(parts[1:])
        if stripped:
            perms.add(stripped)
            for env in ALL_ENVS:
                if env != parts[0]:
                    perms.add(f"{env}.{stripped}")

    # --- 2. Add env prefix (but limit to core envs) ---
    if parts[0] not in ENV_WORDS:
        for pfx in ['dev', 'stg', 'prod', 'test', 'stage']:
            perms.add(f"{pfx}.{base}")

    # --- 3. All word swaps ---
    for old, new in SWAPS:
        if old in base:
            replaced = base.replace(old, new)
            # Don't add if it created something absurdly long
            if len(replaced) < len(base) * 2:
                perms.add(replaced)

    # --- 4. Lab ID variations ---
    for lid in LAB_IDS:
        if lid in base:
            for other in LAB_IDS:
                if other != lid:
                    perms.add(base.replace(lid, other))

    # --- 5. Number variations ---
    for m in re.finditer(r'\d+', base):
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

    # --- 6. CNF code swaps ---
    for cnf in CNF_CODES:
        if cnf in base:
            for other in CNF_CODES:
                if other != cnf:
                    perms.add(base.replace(cnf, other))

    # --- 7. Function code swaps ---
    for func in FUNC_CODES:
        if f'.{func}.' in base:
            for other in FUNC_CODES:
                if other != func:
                    perms.add(base.replace(f'.{func}.', f'.{other}.'))

    # --- 8. SGW city code swaps ---
    sgw_m = re.search(r'sgw([a-z]+)', base)
    if sgw_m:
        city = sgw_m.group(1)
        for other in CITY_CODES:
            if other != city and len(other) == len(city):
                perms.add(base.replace(f'sgw{city}', f'sgw{other}', 1))

    # --- 9. SIP/SSF/SIM/SKA number variations ---
    for family in ['sip', 'ssf', 'sim', 'ska']:
        fm = re.search(rf'\b({family})(\d+)', base)
        if fm:
            num = int(fm.group(2))
            for delta in [-1, 1, -2, 2, 3, -3]:
                new_num = num + delta
                if new_num >= 0:
                    perms.add(base.replace(f'{fm.group(1)}{fm.group(2)}', f'{fm.group(1)}{new_num}'))

    # --- 10. Remove env/lab/platform segments from middle ---
    if len(parts) >= 3:
        filtered = [p for p in parts if p not in ENV_WORDS and p not in LAB_IDS and p not in PLATFORMS]
        if filtered and len(filtered) < len(parts):
            perms.add('.'.join(filtered))
        # Also remove just the last platform segment
        if parts[-1] in PLATFORMS:
            perms.add('.'.join(parts[:-1]))

    # --- 11. Replace any env segment in any position ---
    for pos, part in enumerate(parts):
        if part in ENV_WORDS:
            for env in ENV_WORDS:
                if env != part:
                    new_parts = list(parts)
                    new_parts[pos] = env
                    perms.add('.'.join(new_parts))

    # --- 12. Platform swaps ---
    for plat in PLATFORMS:
        if parts[-1] == plat:
            for other_plat in PLATFORMS:
                if other_plat != plat:
                    perms.add('.'.join(parts[:-1]) + '.' + other_plat)

    # --- 13. msg ↔ api ↔ svc swaps ---
    if '.msg.' in base:
        perms.add(base.replace('.msg.', '.api.'))
        perms.add(base.replace('.msg.', '.svc.'))
    if '.api.' in base:
        perms.add(base.replace('.api.', '.msg.'))

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

    # --- 16. Suffix additions for simple hosts ---
    if len(parts) <= 2:
        for sfx in ['-dev', '-stg', '-test', '-qa', '-prod', '-api', '-admin', '-int', '-ext', '-old', '-new']:
            perms.add(f"{base}{sfx}")
        # Also add subdomain-style suffixes
        for env in ['dev', 'stg', 'test', 'qa', 'prod']:
            perms.add(f"{base}.{env}")

    # --- 17. Special patterns for T-Mobile infra ---
    # serving patterns
    serving_m = re.match(r'serving(\d+)tep(\d+)-(\d+)sgw([a-z]+)(\d+-\d+)', base)
    if serving_m:
        for delta in [-1, 1, -2, 2]:
            new_tep = int(serving_m.group(2)) + delta
            if new_tep > 0:
                perms.add(base.replace(f'tep{serving_m.group(2)}', f'tep{new_tep}'))

    # sippoc → sip variations
    if 'sippoc' in base:
        perms.add(base.replace('sippoc', 'sipprod'))
        perms.add(base.replace('sippoc', 'sipstg'))
        perms.add(base.replace('sippoc', 'sipdev'))

    # shop-gateway variations
    if 'shop-gateway' in base:
        for gw in ['shop-gateway', 'api-gateway', 'gateway', 'api']:
            if gw != 'shop-gateway':
                perms.add(base.replace('shop-gateway', gw))

    # splunk-forwarder variations
    if 'splunk-forwarder' in base:
        perms.add(base.replace('splunk-forwarder', 'splunk'))
        perms.add(base.replace('splunk-forwarder', 'splunk-hec'))

    # --- Clean and score ---
    perms.discard(base)

    def is_prefix_only(p):
        """Check if permutation only differs by adding/changing prefix"""
        p_parts = p.split('.')
        # Same tail (everything after first segment matches original or original's tail)
        if len(p_parts) > 1 and len(parts) >= 1:
            p_tail = '.'.join(p_parts[1:])
            if p_tail == base:
                return True
            if len(parts) > 1 and p_tail == '.'.join(parts[1:]):
                return True
        return False

    def score(p):
        s = 0
        p_parts = p.split('.')

        # Heavy penalty for trivial prefix-only changes
        if is_prefix_only(p):
            s -= 100

        # Reward segment count changes (structural edits)
        if len(p_parts) != len(parts):
            s += 25

        # Reward environment changes within the name (not just prefix)
        for i, pp in enumerate(p_parts):
            if i > 0 and i < len(parts) and pp != parts[i]:
                if pp in ENV_WORDS or parts[i] in ENV_WORDS:
                    s += 18

        # Reward lab ID changes
        for lid in LAB_IDS:
            if lid in p and lid not in base:
                s += 12
                break
        for lid in LAB_IDS:
            if lid in base and lid not in p:
                s += 8
                break

        # Reward region changes
        if ('us-east' in p and 'us-west' in base) or ('us-west' in p and 'us-east' in base):
            s += 18

        # Reward number changes
        if re.search(r'\d', base):
            base_nums = set(re.findall(r'\d+', base))
            p_nums = set(re.findall(r'\d+', p))
            if base_nums != p_nums:
                s += 10

        # Reward platform changes
        for plat in PLATFORMS:
            if plat in p and plat not in base:
                s += 12

        # Reward service name swaps (msg↔api, cnsdg↔sdg, etc.)
        for svc in ['msg', 'api', 'svc', 'cnsdg', 'sdg', 'tfb', 'isp', 'hmt', 'promos']:
            if f'.{svc}.' in p and f'.{svc}.' not in base:
                s += 8

        # Prefer shorter (removed segments = closer to root)
        if len(p) < len(base):
            s += 5

        # Penalize excessively long
        if len(p_parts) > len(parts) + 2:
            s -= 15

        return s

    perms_list = [(p, score(p)) for p in perms if p and len(p) > 0]
    perms_list.sort(key=lambda x: x[1], reverse=True)

    # Take top 9 to account for global dedup
    selected = [p for p, sc in perms_list[:9]]

    # If we don't have 9, fill with more from the pool
    if len(selected) < 9:
        remaining = [p for p, sc in perms_list[9:] if p not in selected]
        selected.extend(remaining[:9 - len(selected)])

    # If still not enough, force-generate prefix/suffix variants
    if len(selected) < 9:
        for pfx in ['dev', 'stg', 'test', 'qa', 'stage', 'api', 'admin', 'int', 'ext', 'www']:
            if len(selected) >= 9:
                break
            candidate = f"{pfx}.{base}"
            if candidate not in selected and candidate != base:
                selected.append(candidate)
        for sfx in ['-dev', '-stg', '-test', '-qa', '-prod', '-api', '-admin']:
            if len(selected) >= 9:
                break
            candidate = f"{base}{sfx}"
            if candidate not in selected and candidate != base:
                selected.append(candidate)

    for p in selected:
        results.add(p + '.t-mobile.com')

# Output
for r in sorted(results):
    print(r)

sys.stderr.write(f"Generated {len(results)} permutations from {len(subdomains)} input subdomains\n")
