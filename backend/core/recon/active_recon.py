import subprocess


def resolve_subdomains(in_file, outfile):
    """
    Resolve subs in infile to outfile
    """
    resolvers_file = f"/work/resources/resolvers/resolvers.txt"

    cmd = ['puredns', 'resolve', in_file, '-r', resolvers_file, '-w', outfile]
    subprocess.run(cmd, text=True, capture_output=True)

    with open(outfile) as f:
        lines = sorted(set(line.strip() for line in f if line.strip()))
    with open(outfile, "w") as f:
        for line in lines:
            f.write(line + "\n")
