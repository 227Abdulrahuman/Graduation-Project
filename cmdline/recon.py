from backend.core.recon.main import run_recon_pipeline
import argparse

parser = argparse.ArgumentParser(description="Recons a root domain")
parser.add_argument("domain", help="Root domain")
parser.add_argument("-cs", "--chunk_size", help="Chunk Size for permutations", default=None)

args = parser.parse_args()

domain = args.domain
chunk_size = args.chunk_size

run_recon_pipeline(domain, int(chunk_size))