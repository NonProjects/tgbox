"""This module stores all Tgbox-unique exceptions."""

class TgboxException(Exception):
    """Base TGBOX Exception"""

# Base Exceptions

class NotInitializedError(TgboxException):
    """The class you try to use isn't initialized"""

class PathIsDirectory(TgboxException):
    """Specified path is Directory"""

class LimitExceeded(TgboxException):
    """Value is out of allowed range"""

class NotATgboxFile(TgboxException):
    """This Telegram mesage isn't a TGBOX file"""

# Crypto Exceptions

class IncorrectKey(TgboxException):
    """Specified key is invalid."""

class ModeInvalid(TgboxException):
    """You should use only decryption or encryption per class"""

class AESError(TgboxException):
    """Invalid AES configuration"""

# Tools Exceptions

class ConcatError(TgboxException):
    """You must concat metadata before using OpenPretender"""

class PreviewImpossible(TgboxException):
    """Can\'t create file preview"""

class DurationImpossible(TgboxException):
    """Can\'t get media duration"""

# Database Exceptions

class InUseException(TgboxException):
    """The DB already exists and in use"""

class BrokenDatabase(TgboxException):
    """Can\'t parse SQLite DB"""

# RemoteBox Exceptions

class RemoteFileNotFound(TgboxException):
    """Seems that there is no requested by you file"""

class SessionUnregistered(TgboxException):
    """Session you trying to use was disconnected"""

class RemoteBoxInaccessible(TgboxException):
    """The RemoteBox you try to use is inaccessible"""

class NotEnoughRights(TgboxException):
    """You don't have rigths for this action"""

# LocalBox Exceptions

class AlreadyImported(TgboxException):
    """LocalBox have file with same ID"""

class NotImported(TgboxException):
    """The file you try to retrieve wasn\'t imported yet"""
