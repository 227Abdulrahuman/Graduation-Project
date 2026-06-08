import random

def generate():
    with open('/work/input_subs.txt', 'r') as f:
        subs = [line.strip() for line in f if line.strip()]

    target_count = len(subs) * 5
    words = ["dev", "staging", "test", "api", "admin", "v1", "v2", "beta", "old", "new", "prod", "internal", "secure", "auth", "login", "app", "demo", "uat", "stg", "qa", "preprod", "sys", "ops", "ci"]
    
    generated = set()
    
    for sub in subs:
        # Generate some good permutations based on words
        parts = sub.split('.')
        # prefix
        generated.add(f"{random.choice(words)}-{sub}")
        generated.add(f"{random.choice(words)}.{sub}")
        if len(parts) > 2:
            generated.add(f"{parts[0]}-{random.choice(words)}.{'.'.join(parts[1:])}")
        else:
            generated.add(f"{random.choice(words)}.{sub}")
        
    while len(generated) < target_count:
        sub = random.choice(subs)
        w = random.choice(words)
        generated.add(f"{w}-{sub}")
        
    perms_list = list(generated)
    if len(perms_list) > target_count:
        perms_list = perms_list[:target_count]
        
    with open('/work/pokemon_perms.txt', 'w') as f:
        for p in perms_list:
            f.write(p + '\n')

if __name__ == '__main__':
    generate()
