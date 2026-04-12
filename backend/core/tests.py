from backend.core.enum.archived_URLs import get_archived_urls


# get_archived_urls("csidmaccess.att.com")

from backend.core.recon.main import run_recon_pipeline


run_recon_pipeline("carigami.fr",chunk_size=500)