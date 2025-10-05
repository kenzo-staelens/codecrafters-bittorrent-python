from .ExtendedHandshake import ExtendedHandshake
from .UT_Metadata import UT_Metadata

extensions = [UT_Metadata]
extension_mapping = {x.name:x for x in extensions}