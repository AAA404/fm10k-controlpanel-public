"""FM10840 control panel. Hardware access belongs exclusively to switchd."""

try:
    from ._package_version import PACKAGE_VERSION as __version__
except ModuleNotFoundError as error:
    if error.name != __name__ + "._package_version":
        raise
    __version__ = "0.2.0"
