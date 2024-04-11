"""This module stores wrappers around Tgbox SQL DB."""

import logging

from typing import (
    Optional, Union,
    AsyncGenerator
)
from os import PathLike
from pathlib import Path

import aiosqlite

from ..defaults import (
    Limits, DOWNLOAD_PATH,
    DEF_NO_FOLDER, DEF_UNK_FOLDER,
)
from ..errors import PathIsDirectory
from ..tools import anext

__all__ = ['SqlTableWrapper', 'TgboxDB', 'TABLES']

logger = logging.getLogger(__name__)

TABLES = {
    'BOX_DATA': (
        ('BOX_CHANNEL_ID', 'BLOB NOT NULL'),
        ('BOX_CR_TIME', 'BLOB NOT NULL'),
        ('BOX_SALT', 'BLOB NOT NULL'),
        ('MAINKEY', 'BLOB'),
        ('SESSION', 'BLOB NOT NULL'),
        ('API_ID', 'BLOB NOT NULL'),
        ('API_HASH', 'BLOB NOT NULL'),
        ('FAST_SYNC_LAST_EVENT_ID', 'BLOB')
    ),
    'FILES': (
        ('ID', 'INTEGER PRIMARY KEY'),
        ('UPLOAD_TIME', 'BLOB NOT NULL'),
        ('PPATH_HEAD', 'BLOB NOT NULL'),
        ('FILEKEY', 'BLOB'),
        ('FINGERPRINT', 'BLOB'),
        ('METADATA', 'BLOB NOT NULL'),
        ('UPDATED_METADATA', 'BLOB')
    ),
    'PATH_PARTS': (
        ('ENC_PART', 'BLOB NOT NULL'),
        ('PART_ID', 'BLOB NOT NULL PRIMARY KEY'),
        ('PARENT_PART_ID', 'BLOB'),
    ),
    'DEFAULTS': (                            # Default value
        ('METADATA_MAX', 'INTEGER NOT NULL', int(Limits.METADATA_MAX)),
        ('FILE_PATH_MAX', 'INTEGER NOT NULL', int(Limits.FILE_PATH_MAX)),

        ('DOWNLOAD_PATH', 'TEXT NOT NULL', str(DOWNLOAD_PATH)),
        ('DEF_NO_FOLDER', 'TEXT NOT NULL', str(DEF_NO_FOLDER)),
        ('DEF_UNK_FOLDER', 'TEXT NOT NULL', str(DEF_UNK_FOLDER))
    )
}
class SqlTableWrapper:
    """A low-level wrapper to SQLite Tables."""
    def __init__(self, aiosql_conn, table_name: str):
        self._table_name = table_name
        self._aiosql_conn = aiosql_conn

    def __repr__(self) -> str:
        return f'<class {self.__class__.__name__}(aiosql_conn, "{self._table_name}")>'

    async def __aiter__(self) -> tuple:
        """Will yield rows as self.select without ``sql_statement``"""
        async for row in self.select():
            yield row

    @property
    def table_name(self) -> str:
        """Returns table name"""
        return self._table_name

    async def count_rows(self) -> int:
        """Execute ``SELECT count(*) from TABLE_NAME``"""

        logger.debug(f'SELECT count(*) FROM {self._table_name}')

        cursor = await self._aiosql_conn.execute(
            f'SELECT count(*) FROM {self._table_name}'
        )
        return (await cursor.fetchone())[0]

    async def select(self, sql_tuple: Optional[tuple] = None) -> AsyncGenerator:
        """
        If ``sql_tuple`` isn't specified, then will be used
        ``(SELECT * FROM TABLE_NAME, ())`` statement.
        """
        if not sql_tuple:
            sql_tuple = (f'SELECT * FROM {self._table_name}',())

        logger.debug(f'self._aiosql_conn.execute(*{sql_tuple})')

        cursor = await self._aiosql_conn.execute(*sql_tuple)
        async for row in cursor: yield row

    async def select_once(self, sql_tuple: Optional[tuple] = None) -> tuple:
        """
        Will return first row which match the ``sql_tuple``,
        see ``select()`` method for ``sql_tuple`` details.
        """
        return await anext(self.select(sql_tuple=sql_tuple))

    async def insert(
            self, *args, sql_statement: Optional[str] = None,
            commit: bool=True) -> None:
        """
        If ``sql_statement`` isn't specified, then will be used
        ``INSERT INTO TABLE_NAME values (...)``.

        This method doesn't check if you insert correct data
        or correct amount of it, you should know DB structure.
        """
        if not sql_statement:
            sql_statement = (
                f'INSERT INTO {self._table_name} values ('
                + ('?,' * len(args))[:-1] + ')'
            )
        logger.debug(f'self._aiosql_conn.execute({sql_statement}, {args})')
        await self._aiosql_conn.execute(sql_statement, args)

        if commit:
            logger.debug('self._aiosql_conn.commit()')
            await self._aiosql_conn.commit()

    async def execute(self, sql_tuple: tuple, commit: bool=True):
        logger.debug(f'self._aiosql_conn.execute(*{sql_tuple})')
        result = await self._aiosql_conn.execute(*sql_tuple)
        if commit:
            logger.debug('self._aiosql_conn.commit()')
            await self._aiosql_conn.commit()
        return result # Returns Cursor object

    async def commit(self) -> None:
        logger.info('SqlTableWrapper._aiosql_conn.commit()')
        await self._aiosql_conn.commit()

class TgboxDB:
    def __init__(self, db_path: Union[PathLike, str]):
        """
        Arguments:
            db_path (``PathLike``, ``str``):
                Path to the Tgbox DB.
        """
        if isinstance(db_path, PathLike):
            self._db_path = db_path
        else:
            self._db_path = Path(db_path)

        if self._db_path.is_dir():
            raise PathIsDirectory('Path is directory.')

        self._db_path.parent.mkdir(exist_ok=True, parents=True)

        self._aiosql_db = None
        self._aiosql_db_is_closed = None
        self._initialized = False

        self._name = self._db_path.name

    def __str__(self) -> str:
        return f'{self.__class__.__name__}("{str(self._db_path)}") # {self._initialized=}'

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}("{str(self._db_path)}")'

    @property
    def name(self) -> str:
        """Returns TgboxDB name"""
        return self._name

    @property
    def db_path(self) -> PathLike:
        """Returns a path to TgboxDB file"""
        return self._db_path

    @property
    def initialized(self) -> bool:
        """Will return True if TgboxDB is initialized"""
        return self._initialized

    @property
    def closed(self) -> bool:
        """
        This method will return ``None`` if DB wasn't opened,
        False if it's still opened, True if it's was closed.
        """
        return self._aiosql_db_is_closed

    @staticmethod
    async def create(db_path: Union[str, PathLike]) -> 'TgboxDB':
        """Will initialize TgboxDB"""
        return await TgboxDB(db_path).init()

    async def close(self) -> None:
        """Will close TgboxDB"""
        logger.info(f'{self._db_path} @ self._aiosql_db.close()')
        await self._aiosql_db.close()
        self._aiosql_db_is_closed = True

    async def init(self) -> 'TgboxDB':
        logger.debug(f'tgbox.api.db.TgboxDB.init("{self._db_path}")')

        logger.info(f'Opening SQLite connection to {self._db_path}')
        self._aiosql_db = await aiosqlite.connect(self._db_path)

        for table, data in TABLES.items():
            try:
                columns = ', '.join((f'{i[0]} {i[1]}' for i in data))
                await self._aiosql_db.execute(
                    f'CREATE TABLE {table} ({columns})'
                )
                if table == 'DEFAULTS':
                    sql_statement = (
                        f'INSERT INTO {table} VALUES ('
                        + ('?,' * len(data))[:-1] + ')'
                    )
                    await self._aiosql_db.execute(
                        sql_statement, [i[2] for i in data]
                    )
            except aiosqlite.OperationalError: # Table exists
                # The code below will update TgboxDB schema if it's outdated
                table_columns = await self._aiosql_db.execute(
                    f'PRAGMA table_info({table})'
                )
                table_columns = set((i[1] for i in await table_columns.fetchall()))
                required_columns = set((i[0] for i in data))

                if table_columns != required_columns:
                    logger.info(f'TgboxDB {self._db_path} seems outdated. Updating...')
                    table_columns &= required_columns

                    logger.debug(f'CREATE TABLE "updated!{table}" ({columns})')

                    await self._aiosql_db.execute(
                        f'CREATE TABLE "updated!{table}" ({columns})'
                    )
                    table_columns_str = ', '.join(table_columns)

                    logger.debug(
                        f"""INSERT INTO "updated!{table}" ({table_columns_str}) """
                        f"""SELECT {table_columns_str} FROM {table}"""
                    )
                    await self._aiosql_db.execute(
                        f"""INSERT INTO "updated!{table}" ({table_columns_str}) """
                        f"""SELECT {table_columns_str} FROM {table}"""
                    )
                    logger.debug(f'DROP TABLE {table}')
                    await self._aiosql_db.execute(f'DROP TABLE {table}')

                    logger.debug(f'ALTER TABLE "updated!{table}" RENAME TO {table}')
                    await self._aiosql_db.execute(
                        f'ALTER TABLE "updated!{table}" RENAME TO {table}'
                    )
        logger.info('TgboxDB._aiosql_conn.commit()')
        await self._aiosql_db.commit()
        self._aiosql_db_is_closed = False

        tables = await self._aiosql_db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        for table in (await tables.fetchall()):
            setattr(self, table[0], SqlTableWrapper(self._aiosql_db, table[0]))

        self._initialized = True
        return self
