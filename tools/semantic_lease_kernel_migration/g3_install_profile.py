"""Read the candidate nftProfile before signing the immutable g3 owner."""
from . import boot_dispatcher as boot
from .g3_contract import NFT_FORMAT, listing_profile


def read_nft_profile(nft_path, nft_sha256):
    binding = {'path': nft_path, 'sha256': nft_sha256}
    inventory = boot.document(boot.command(binding, ['-j', 'list', 'tables']))
    if not isinstance(inventory, dict) or inventory.keys() != {'nftables'}:
        raise ValueError(NFT_FORMAT)
    rows = inventory['nftables']
    if not isinstance(rows, list) or not rows:
        raise ValueError(NFT_FORMAT)
    return listing_profile(rows[0])
