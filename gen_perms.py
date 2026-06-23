import sys
import re

subdomains = []
with open('/work/subs_input.txt') as f:
    for line in f:
        line = line.strip()
        if line:
            subdomains.append(line)

# Track all results to avoid duplicates
results = set()

# Environment words for swapping
env_prefixes = ['dev', 'stg', 'stage', 'staging', 'test', 'qa', 'prod', 'int', 'ext', 'admin', 'api', 'uat', 'www']
env_suffix_segments = {'lab', 'stg', 'dev', 'qa', 'prod', 'eng', 'uat', 'test', 'npe'}
env_swaps = [
    ('stg', 'dev'), ('stg', 'prod'), ('stg', 'qa'), ('stg', 'stage'),
    ('dev', 'stg'), ('dev', 'prod'), ('dev', 'qa'),
    ('lab', 'eng'), ('lab', 'stg'), ('lab', 'dev'), ('lab', 'prod'),
    ('eng', 'lab'), ('eng', 'stg'),
    ('stage', 'staging'), ('staging', 'stage'),
    ('qlab', 'plab'), ('plab', 'qlab'), ('qlab', 'ilab'), ('plab', 'ilab'), ('ilab', 'qlab'), ('ilab', 'plab'),
    ('us-east-1', 'us-west-2'), ('us-west-2', 'us-east-1'),
    ('prod', 'stg'), ('prod', 'dev'),
    ('int', 'ext'), ('ext', 'int'),
    ('npe', 'stg'), ('npe', 'dev'), ('npe', 'prod'),
    ('qat', 'dev'), ('qat', 'stg'),
    ('-stg', '-dev'), ('-dev', '-stg'), ('-stg', '-prod'), ('-dev', '-prod'),
]

for sub in subdomains:
    base = sub.replace('.t-mobile.com', '')
    parts = base.split('.')
    count = 0
    perms_for_this = set()

    # Strategy 1: Environment prefix variations
    for pfx in env_prefixes:
        if count >= 8: break
        # Don't add prefix if first part is already that prefix
        if parts[0] == pfx:
            continue
        candidate = f"{pfx}.{base}"
        if candidate not in perms_for_this and candidate != base:
            perms_for_this.add(candidate)
            count += 1

    # Strategy 2: Remove first segment (strip prefix)
    if count < 8 and len(parts) > 1:
        candidate = '.'.join(parts[1:])
        if candidate not in perms_for_this and candidate != base:
            perms_for_this.add(candidate)
            count += 1

    # Strategy 3: Environment swaps within the subdomain
    if count < 8:
        for old, new in env_swaps:
            if count >= 8: break
            if old in base:
                candidate = base.replace(old, new)
                if candidate not in perms_for_this and candidate != base:
                    perms_for_this.add(candidate)
                    count += 1

    # Strategy 4: Number permutations
    if count < 8:
        # Find all number sequences
        num_matches = list(re.finditer(r'(\d+)', base))
        if num_matches:
            for m in num_matches:
                if count >= 8: break
                num_str = m.group(1)
                num = int(num_str)
                for delta in [1, -1, 2, -2, 3, 4, 5, 6, 7, 8]:
                    if count >= 8: break
                    new_num = num + delta
                    if new_num < 0:
                        continue
                    new_num_str = str(new_num).zfill(len(num_str))
                    candidate = base[:m.start(1)] + new_num_str + base[m.end(1):]
                    if candidate not in perms_for_this and candidate != base:
                        perms_for_this.add(candidate)
                        count += 1

    # Strategy 5: Change last segment to common env words
    if count < 8:
        for sfx in env_suffix_segments:
            if count >= 8: break
            if parts[-1] in env_suffix_segments and parts[-1] != sfx:
                new_parts = parts[:-1] + [sfx]
                candidate = '.'.join(new_parts)
                if candidate not in perms_for_this and candidate != base:
                    perms_for_this.add(candidate)
                    count += 1

    # Strategy 6: Add api/internal/admin prefix to short names
    if count < 8 and len(parts) <= 2:
        for inner in ['api', 'internal', 'admin', 'www', 'cdn', 'mail', 'vpn']:
            if count >= 8: break
            candidate = f"{inner}.{base}"
            if candidate not in perms_for_this and candidate != base:
                perms_for_this.add(candidate)
                count += 1

    # Strategy 7: Append common suffixes
    if count < 8:
        for suffix in ['-dev', '-stg', '-test', '-qa', '-prod', '-backup', '-old', '-new']:
            if count >= 8: break
            candidate = base + suffix
            if candidate not in perms_for_this and candidate != base:
                perms_for_this.add(candidate)
                count += 1

    # Strategy 8: Regional variations for kube/dab hosts
    if count < 8 and 'us-east-1' in base:
        candidate = base.replace('us-east-1', 'us-west-2')
        if candidate not in perms_for_this and candidate != base:
            perms_for_this.add(candidate)
            count += 1
    if count < 8 and 'us-west-2' in base:
        candidate = base.replace('us-west-2', 'us-east-1')
        if candidate not in perms_for_this and candidate != base:
            perms_for_this.add(candidate)
            count += 1

    # Strategy 9: lab environment variations for msg hosts
    if count < 8:
        if '.lab.' in base:
            candidate = base.replace('.lab.', '.eng.')
            if candidate not in perms_for_this and candidate != base:
                perms_for_this.add(candidate)
                count += 1
        elif '.eng.' in base:
            candidate = base.replace('.eng.', '.lab.')
            if candidate not in perms_for_this and candidate != base:
                perms_for_this.add(candidate)
                count += 1

    # Strategy 10: stg prefix strip or add
    if count < 8 and parts[0] == 'stg':
        candidate = '.'.join(parts[1:])
        if candidate not in perms_for_this and candidate != base:
            perms_for_this.add(candidate)
            count += 1

    # Pad to exactly 8 if needed
    if count < 8:
        fillers = ['dev', 'stg', 'test', 'qa', 'prod', 'uat', 'int', 'ext', 'stage', 'api', 'admin']
        i = 0
        while count < 8 and i < len(fillers):
            candidate = f"{fillers[i]}.{base}"
            if candidate not in perms_for_this and candidate != base:
                perms_for_this.add(candidate)
                count += 1
            i += 1

    # Add all permutations for this subdomain with .t-mobile.com suffix
    for p in perms_for_this:
        full = p + '.t-mobile.com'
        if full != sub:
            results.add(full)

# Output all results
for r in sorted(results):
    print(r)
