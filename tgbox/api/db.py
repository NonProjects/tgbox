"""This module stores wrappers around Tgbox SQL DB."""

import logging

from os import PathLike
from pathlib import Path
from collections import namedtuple
from typing import Optional, Union, AsyncGenerator

import aiosqlite

from ..errors import PathIsDirectory
from ..tools import anext
from .. import defaults


__all__ = ['SqlTableWrapper', 'TgboxDB', 'TABLES']

logger = logging.getLogger(__name__)

# TABLES is a dictionary that describes the structure of Sqlite database.
# Here, key is Table name, and elements of value tuple (other tuples) are
# individual columns with their respective types. Columns can contain 2 to
# 3 elements, with third being the "autofill" value. If "autofill" (third)
# value is present in at least one column tuple, then IT MUST BE PRESENT
# IN ALL COLUMNS OF THIS TABLE.
#
# The main difficulty in designing the table migration is NOT NULL columns
# in the new schema. If we were stupidly add the "NOT NULL" column e.g
# to the *existing* FILES table, then migration will fail miserably
# because of lack of the value for this new column in our old rows. We
# can't use "autofill" values here, because it will break the Table
# creation for the new users. So the only correct way will be either
# dropping "NOT NULL" from new column Type, or just adding the DEFAULT
# to it. E.g: ('ID2', 'INTEGER NOT NULL DEFAULT -1'). Here, -1 in Type
# definition is the default value. Of course, we will need to make
# API in-code checks for this value and process accordingly.
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
    # If you add any values to DEFAULTS, update the
    # tgbox.utils.RemoteBoxDefaults, as well as all
    # RemoteBoxDefaults() in remote.py, because they
    # are not automatic
    'DEFAULTS': (                            # Autofill value. See comment higher
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
        where = where if where else {}

        v = ''
        for column, _ in kwargs:
            v += f'{column}=?,'

        v = v.rstrip(',')

        w = ''
        if where:
            w = 'WHERE ' + ' AND '.join(f'{column}=?' for column in where)

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
           f'# {self._initialized=}')

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
        return bool(self._aiosql_db_is_closed)

    @staticmethod
    async def create(db_path: Union[str, PathLike]) -> 'TgboxDB':
        """Will initialize TgboxDB"""
        return await TgboxDB(db_path).init()

    async def close(self) -> None:
        """Will close TgboxDB"""
        logger.info(f'{self._db_path} @ self._aiosql_db.close()')
        try:
            await self._aiosql_db.close()
        except BaseException as e:
            raise ValueError('Database can not be closed') from e

        self._aiosql_db_is_closed = True

    async def _init(self) -> 'TgboxDB':
        logger.debug(f'tgbox.api.db.TgboxDB.init("{self._db_path}")')

        logger.info(f'Opening SQLite connection to {self._db_path}')
        self._aiosql_db = await aiosqlite.connect(self._db_path)

        available_tables = await self._aiosql_db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        available_tables = await available_tables.fetchall()
        available_tables = set(i[0] for i in available_tables)\
            if available_tables else set()

        # DEFAULTS is special case. If DEFAULTS is presented in LocalBox,
        # we want to be sure that it contains data row. Otherwise user
        # won't be able to use this Box at all. Here we do this check
        if 'DEFAULTS' in available_tables:
            defaults_row = await self._aiosql_db.execute(
                'SELECT 1 FROM DEFAULTS LIMIT 1'
            )
            if not await defaults_row.fetchone():
                logger.info('DEFAULTS table exists, but no data on it. Fixing..')
                await self._aiosql_db.execute('DROP TABLE DEFAULTS')
                available_tables.remove('DEFAULTS')

        column_pragma = namedtuple('ColumnPragma',
            ('cid', 'name', 'type', 'notnull', 'dflt_value', 'pk')
        )

        for table, data in TABLES.items():
            if table not in available_tables:
                logger.info('Table %s is not presented in database. '
                    'We will create it', table)

                columns = ', '.join((f'{i[0]} {i[1]}' for i in data))

                autofill_exists = False
                autofill_correct = True
                for c in data:
                    if autofill_correct and len(c) < 3:
                        autofill_correct = False

                    elif not autofill_exists and len(c) > 2:
                        autofill_exists = True

                    if autofill_exists and not autofill_correct:
                        raise ValueError(
                            f'At least one of your db.TABLES {table=} columns '
                            'include autofill value, but NOT ALL. All columns '
                            'MUST have autofill values if at least one includes it!'
                        )

                await self._aiosql_db.execute(
                    f'CREATE TABLE IF NOT EXISTS {table} ({columns})'
                )
                if autofill_exists:
                    table_w = SqlTableWrapper(self._aiosql_db, table)
                    default_columns = {c[0]: c[-1] for c in data}
                    await table_w.insert(**default_columns)
            else:
                # This will update TgboxDB schema if it's outdated

                # This query will get all unique columns for the current
                # TABLE, e.g FILES (will change in loop).
                unique_columns = await self._aiosql_db.execute(
                    "SELECT ii.name AS column_name "
                   f"FROM pragma_index_list('{table}') AS il "
                    "JOIN pragma_index_info(il.name) AS ii "
                    "WHERE il.\"unique\" = 1 "
                    "AND il.origin = 'u' "
                    "AND (SELECT COUNT(*) FROM pragma_index_info(il.name)) = 1;"
                )
                unique_columns = await unique_columns.fetchall()
                unique_columns = set(c[0] for c in unique_columns)\
                    if unique_columns else ()

                table_info = await self._aiosql_db.execute(
                    f'PRAGMA table_info({table})')

                old_columns_data = set()
                pragmas = []

                for c_pragma in await table_info.fetchall():
                    c_pragma = column_pragma(*c_pragma)
                    pragmas.append(c_pragma)

                    c_properties = (
                        ('name', c_pragma.name),
                        ('type', c_pragma.type.upper()),
                        ('notnull', bool(c_pragma.notnull)),
                        ('pk', bool(c_pragma.pk)),
                        ('unique', c_pragma.name in unique_columns),
                        ('dflt_exist', bool(c_pragma.dflt_value))
                    )
                    old_columns_data.add(frozenset(c_properties))

                current_columns_data = set()
                for c in data:
                    c_1 = ' '.join(c[1].upper().split())

                    c_properties = (
                        ('name', c[0].strip(' ')),
                        ('type', c_1.split()[0]),
                        ('notnull', ' NOT NULL' in c_1),
                        ('pk', ' PRIMARY KEY' in c_1),
                        ('unique', ' UNIQUE' in c_1),
                        ('dflt_exist', ' DEFAULT' in c_1)
                    )
                    current_columns_data.add(frozenset(c_properties))

                if old_columns_data == current_columns_data:
                    logger.debug('Table schema for Table "%s" is up to date', table)
                    continue

                logger.info(f'TgboxDB {self._db_path} is outdated. Updating...')

                table_columns = [i[:2] for i in data]
                updated_table_name = f'updated___{table}'

                columns_schema = [' '.join(i) for i in table_columns]
                columns_schema = ', '.join(columns_schema).rstrip(', ')

                await self._aiosql_db.execute(
                    f'DROP TABLE IF EXISTS "{updated_table_name}"'
                )
                await self._aiosql_db.execute(
                    f'CREATE TABLE "{updated_table_name}" ({columns_schema})'
                )
                current_table_columns = [i[0] for i in TABLES[table]]

                available_columns = []
                for c in pragmas:
                    if c.name not in current_table_columns:
                        logger.info(
                            'Column %s (table %s) is not presented in '
                            'updated database schema, thus, will be '
                            'dropped.', c.name, table)
                        continue

                    available_columns.append(c.name)

                if (available_columns_str := ','.join(available_columns)):
                    await self._aiosql_db.execute(
                        f'INSERT INTO "{updated_table_name}" '
                        f'({available_columns_str}) '
                        f'SELECT {available_columns_str} FROM {table}'
                    )
                logger.debug(f'DROP TABLE {table}')
                await self._aiosql_db.execute(f'DROP TABLE {table}')

                logger.debug(f'ALTER TABLE "{updated_table_name}" RENAME TO {table}')
                await self._aiosql_db.execute(
                    f'ALTER TABLE "{updated_table_name}" RENAME TO {table}'
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

    async def init(self) -> 'TgboxDB':
        """This method will initialize and prepare Database"""
        try:
            return await self._init()
        except BaseException as e:
            if self._aiosql_db:
                await self.close()
            raise e
