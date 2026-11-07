"""Future M2 image alias: retain legacy validation plus one exact CI origin.

The installed MCP's original image has no revision label. Its existing reviewed
CI binding and two exact archive envelopes identify that one original image.
This adapter is not part of the frozen 235-source execution compiler. A new
sealed compiler must explicitly select it and close both helper dependencies.
Historical artifact receipts establish source bytes, never runtime authority.
"""
from tools.semantic_application_cutover.image_custody import *
from tools.semantic_application_cutover import image_custody as _legacy
from tools.acquisition_read_native import image_custody as _qualified

QUALIFIED_HELPER_SHA256 = '5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8'
MCP_IMAGE = 'sha256:47e42435404d4d4cb5ca24473ac22192b375c0bf602b4e35f5864d0894a69903'
MCP_SOURCE = 'd2454f3cb8cd410d284b9dc78349a170187aea1c'
MCP_ARCHIVES = frozenset({
    'b0fe7783bec0b2c9b0e2f46fcc40d4cd4bcc58ce9d21e3fb0f685be3de00e358',
    '457d3ddc2a1a844a8e7851f75a7f3ada37b5f737d02c41ccbc9d11319a175f9b'})
MCP_BINDING = {'schema': 'ouf.acquisition-image-source-by-qualified-ci-manifest.v1',
    'sourceCommit': MCP_SOURCE, 'imageId': MCP_IMAGE,
    'compressedArchiveSha256': 'e2e9d7c11a168b6f2112ec5b21c21a087ae093a927775f4adf619fd10a28a990',
    'stagedReceiptHash': '64accc3b0027ea73cfb486180001cd727971aa0f378441894e4293968061ded8',
    'frozenPlanHash': 'bffeab6076a703b6bca567b6ab69366b0f824a8a57cee4ca21a531be63a0eb93'}
MCP_BINDING_HASH = '396300e851acabcd5be070c885790ca0f9abb9f51f38af7c717db1057470106a'


def archive(stream, expected_tar_sha256, expected_image, expected_source):
    if expected_image != MCP_IMAGE:
        return _legacy.archive(stream, expected_tar_sha256, expected_image, expected_source)
    require(digest(MCP_BINDING) == MCP_BINDING_HASH and expected_source == MCP_SOURCE
        and expected_tar_sha256 in MCP_ARCHIVES, 'EXACT_CURRENT_MCP_CI_ARCHIVE_BINDING_REQUIRED')
    return _qualified.archive(stream, expected_tar_sha256, expected_image, expected_source,
        ci_source_binding=dict(MCP_BINDING))
