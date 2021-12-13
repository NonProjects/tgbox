"""This module stores all Tgbox-unique errors."""

# Base Exceptions

class IncorrectKey(Exception):
    """Specified key is invalid."""

class NotInitializedError(Exception):
    """The class you try to use isn't initialized"""

class PathIsDirectory(Exception):
    """Specified path is Directory"""

# Crypto Exceptions

class ModeInvalid(Exception):
    """You should use only decryption or encryption per class"""

class AESError(Exception):
    """Invalid AES configuration"""

# Tools Exceptions

class ConcatError(Exception):
    """You must concat metadata before using OpenPretender"""

class PreviewImpossible(Exception):
    """Can\'t create file preview"""

class DurationImpossible(Exception):
    """Can\'t get media duration"""

# Database Exceptions

class InUseException(Exception):
    """The DB already exists and in use"""

class BrokenDatabase(Exception):
    """Can\'t parse SQLite DB"""

# RemoteBox Exceptions

class RemoteFileNotFound(Exception):
    """Seems that there is no requested by you file"""

# LocalBox Exceptions

class AlreadyImported(Exception):
    """LocalBox have file with same ID"""

class NotImported(Exception):
    """The file you try to retrieve wasn\'t imported yet"""
