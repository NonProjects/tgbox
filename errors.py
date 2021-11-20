# Base Exceptions

class IncorrectKey(Exception):
    '''Specified key is invalid.'''

class NotInitializedError(Exception):
    '''The class you try to use isn't initialized'''

class InUseException(Exception):
    '''The DB already exists and in use'''

class BrokenDatabase(Exception):
    '''Can\'t parse SQLite DB'''

class AlreadyImported(Exception):
    '''LocalBox have file with same ID'''

# Crypto Exceptions

class ModeInvalid(Exception):
    '''You should use only decryption or encryption per class'''

class AESError(Exception):
    '''Invalid AES configuration'''

# Tools Exceptions

class ConcatError(Exception):
    '''You must concat metadata before using OpenPretender'''

class PreviewImpossible(Exception):
    '''Can\'t create file preview'''

class DurationImpossible(Exception):
    '''Can\'t get media duration'''

# Database Exceptions

class PathIsDirectory(Exception):
    '''Specified path is Directory'''
