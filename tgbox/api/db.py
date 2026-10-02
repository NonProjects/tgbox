"""This module stores wrappers around Tgbox SQL DB."""

import logging

from typing import (
    Optional, Union,
    AsyncGenerator
)
from os import PathLike
from pathlib import Path

import aiosqlite

from ..errors import PathIsDirectory
from ..tools import anext
from .. import defaults


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
        ('PARENT_PART_ID', 'BLOB')
    ),
    # If you add any values to DEFAULTS, then update the
    # tgbox.utils.RemoteBoxDefaults, as well as all
    # RemoteBoxDefaults() in remote.py, because they
    # are not automatic
    'DEFAULTS': (                            # Default value
        ('METADATA_MAX', 'INTEGER NOT NULL', int(defaults.Limits.METADATA_MAX)),
        ('FILE_PATH_MAX', 'INTEGER NOT NULL', int(defaults.Limits.FILE_PATH_MAX)),

        ('DOWNLOAD_PATH', 'TEXT NOT NULL', str(defaults.DOWNLOAD_PATH)),
        ('DEF_NO_FOLDER', 'TEXT NOT NULL', str(defaults.DEF_NO_FOLDER)),
        ('DEF_UNK_FOLDER', 'TEXT NOT NULL', str(defaults.DEF_UNK_FOLDER)),
        ('FAST_SYNC_ENABLED', 'INTEGER NOT NULL', int(defaults.FAST_SYNC_ENABLED))
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

    async def insert(self, or_ignore: bool=False, commit: bool=True, **kwargs) -> None:
        """
        Proxy to INSERT INTO sqlite statement

        You should specify kwargs, where kwarg is name of a column,
        and it's value is a value you wish to INSERT.

        If ``or_ignore`` is ``True``, will issue ``INSERT OR IGNORE``
        instead of plain ``INSERT INTO``
        """
        sql_statement = 'INSERT{0}INTO {1} ({2}) VALUES ({3})'
        kwargs = tuple(i[0] for i in zip(kwargs.items()))

        c = ''
        for column, _ in kwargs:
            c += f'{column},'

        c = c.rstrip(',')

        q = ('?,' * len(kwargs)).rstrip(',')
        ignore = ' OR IGNORE ' if or_ignore else ' '

        sql_statement = sql_statement.format(ignore, self._table_name, c, q)

        args = tuple(i[1] for i in kwargs)

        logger.debug('self._aiosql_conn.execute("%s", %s)', sql_statement, args)
        await self._aiosql_conn.execute(sql_statement, args)

        if commit:
            logger.debug('self._aiosql_conn.commit()')
            await self._aiosql_conn.commit()

    async def update(self, where: Optional[dict] = None,
            commit: bool=True, **kwargs) -> None:
        """
        Proxy to UPDATE sqlite statement

        You can use this coroutine for easier ``UPDATE`` usage. You
        should provide kwargs, where kwarg is name of a column,
        and its value is value. For example:

        ``await db.BOX_DATA.insert(BOX_CHANNEL_ID=box_channel_id)``

        If you need ``WHERE`` clause, you can provide a ``where``
        dict(). In ``where`` dict, keys must be column names,
        and values must be values. E.g this:

            ``PATH_PARTS.insert(PART_ID=b'updated', where={'PART_ID': b'old'})``

        Will transform into the next SQLite statement:

            ``UPDATE PATH_PARTS SET PART_ID=b'updated' WHERE PART_ID=b'old'``
        """
        sql_statement = 'UPDATE {0} SET {1} {2}'
        kwargs = tuple(i[0] for i in zip(kwargs.items()))

        v = ''
        for column, value in kwargs:
            v += f'{column}=?,'

        v = v.rstrip(',')

        w = ''
        if where:
            w += 'WHERE '
            for column, value in where.items():
                w += f'{column}=? AND'

            w = w.removesuffix('AND')

        sql_statement = sql_statement.format(self._table_name, v, w)
        args = (*(i[1] for i in kwargs), *(i for i in where.values()))

        logger.debug('self._aiosql_conn.execute("%s", %s)', sql_statement, args)
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
        return (
           f'{self.__class__.__name__}("{str(self._db_path)}") '
            '# {self._initialized=}')

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
                table_columns_ = await self._aiosql_db.execute(
                    f'PRAGMA table_info({table})'
                )
                old_table_columns = set()
                for i in await table_columns_.fetchall():
                    column = ( # Does not currently respect UNIQUE and will constantly
                        i[1],  # re-generate Table on startup. TODO.
                        i[2] + (' NOT NULL' if i[3] else '')\
                             + (' PRIMARY KEY' if i[5] else '')
                    )
                    old_table_columns.add(column)

                required_columns = set((i[0:2] for i in data))

                if old_table_columns == required_columns:
                    continue # Schemas are about same

                logger.info(f'TgboxDB {self._db_path} seems outdated. Updating...')

                table_columns = [i[:2] for i in data]
                old_table_columns = set(i[0] for i in old_table_columns)

                old_table_columns_str = ', '.join(
                    i[0] for i in table_columns
                    if i[0] in old_table_columns
                )
                new_table_columns = table_columns[len(old_table_columns):]

                old_rows = await self._aiosql_db.execute(
                   f'SELECT {old_table_columns_str} from {table}')

                columns_schema = [' '.join(i) for i in table_columns]
                columns_schema = ','.join(columns_schema).rstrip(',')

                logger.debug(f'CREATE TABLE "updated!{table}" ({columns})')

                await self._aiosql_db.execute(
                    'CREATE TABLE IF NOT EXISTS '
                   f'"updated!{table}" ({columns_schema})'
                )
                new_values = []
                for column in new_table_columns:
                    for default_data in data:
                        if default_data[0] == column[0]:
                            if len(default_data) > 2:
                                new_values.append(default_data[2])
                            else:
                                new_values.append(None)

                q = ('?,'*len(table_columns)).rstrip(',')

                columns_insert = (i[0] for i in table_columns)
                columns_insert = ','.join(columns_insert).rstrip(',')

                while (fetch := await old_rows.fetchone()):
                    await self._aiosql_db.execute(
                       f'INSERT INTO "updated!{table}" '
                       f'({columns_insert}) VALUES ({q})',
                        (*fetch, *new_values)
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
            'SELECT name FROM sqlite_master WHERE type="table"'
        )
        for table in (await tables.fetchall()):
            setattr(self, table[0], SqlTableWrapper(self._aiosql_db, table[0]))

        self._initialized = True
        return self
