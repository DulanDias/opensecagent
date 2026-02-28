# OpenSecAgent - Autonomous Server Cybersecurity Expert Bot
try:
    from importlib.metadata import version as _version
    __version__ = _version("opensecagent")
except Exception:
    __version__ = "0.2.7"
