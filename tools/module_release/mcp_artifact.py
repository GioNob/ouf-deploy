"""Read the acquisition CI envelope. The original ZIP digest pins every member."""
import hashlib
import json

from .contract import checksum, digest, image_ids, require


def verify(z, ci, target, transport, *, image_defaults=None):
    metadata = {"image-id.txt", "image-config.json", "source-commit.txt", "capabilities.json"}
    require(sorted(z.namelist()) == sorted(metadata | {"SHA256SUMS", "image.tar.gz"})
            and sum(i.file_size for i in z.infolist()) <= 64 << 20
            and all(z.getinfo(k).file_size <= 1 << 20 for k in metadata | {"SHA256SUMS"}), "ARTIFACT_LAYOUT")
    files = {k: z.read(k) for k in metadata}
    sums = {k: hashlib.sha256(v).hexdigest() for k, v in files.items()}
    with z.open("image.tar.gz") as archive:
        sums["image.tar.gz"] = checksum(archive, target)
    require(sorted(z.read("SHA256SUMS").decode("ascii").splitlines()) ==
            sorted(f"{v}  {k}" for k, v in sums.items()), "PUBLISHER_CHECKSUMS_CHANGED")
    tested = files["source-commit.txt"].decode("ascii").strip()
    require(tested == ci["publisherCommit"], "CI_PROVENANCE_CHANGED")
    tag = ci["imageName"] + ":" + ci["tag"]
    inspected, = json.loads(files["image-config.json"])
    require(isinstance(inspected["Config"], dict), "ARCHIVED_DEFAULTS_CHANGED")
    with z.open("image.tar.gz") as archive:
        ids = image_ids(archive, tag, ci["repository"], tested, publisher_config=inspected["Config"], image_defaults=image_defaults)
    ident = files["image-id.txt"].decode("ascii").strip()
    require(ident == inspected["Id"] and ident in ids and (transport or ci["imageId"] in ids), "IMAGE_ID_CHANGED")
    receipt = {"archiveSha256": sums["image.tar.gz"], "capabilitiesSha256": sums["capabilities.json"],
               "imageTag": tag, "testedCommit": tested, "publisherImageId": ident, "verifiedImageIds": sorted(ids)}
    # This publisher has no run/attempt/tree in its ZIP. The protected transport
    # attests those fields after consulting GitHub. Root pins the receipt digest.
    coordinates = {k: ci[k] for k in ("repository", "workflow", "pullRequest", "sourceBranch", "sourceCommit",
                                      "sourceTree", "runId", "runAttempt", "artifactId", "zipSha256")}
    stamp = digest({**coordinates, **receipt})
    require(transport or stamp == ci["transportSha256"], "TRANSPORT_PROVENANCE_CHANGED")
    return {**receipt, "transportSha256": stamp}
