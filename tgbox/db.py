"""This module stores wrappers around Tgbox SQL DB."""

import aiosqlite

from pathlib import Path
from typing import Optional, Union, AsyncGenerator

from .errors import PathIsDirectory
from .tools import anext


__all__ = ['SqlTableWrapper', 'TgboxDB']

class SqlTableWrapper:
    """A low-level wrapper to SQLite Tables."""
    def __init__(self, aiosql_conn, table_name: str):
        self._table_name = table_name
        self._aiosql_conn = aiosql_conn
    
    async def __aiter__(self) -> tuple:
        """Will yield rows as self.select without ``sql_statement``"""
        async for row in self.select():
            yield row
   
    @property
    def table_name(self) -> str:
        """Returns table name"""
        return self._table_name

    async def count_rows(self) -> int:
        """Execute SELECT count(*) from TABLE_NAME"""
        async with self._aiosql_conn.execute(f'SELECT count(*) FROM {self._table_name}') as cursor:
            return (await cursor.fetchone())[0]

    async def select(self, *, sql_tuple: Optional[tuple] = None) -> AsyncGenerator:
        """
        If ``sql_tuple`` isn't specified, then will be used
        (SELECT * FROM TABLE_NAME, ()) statement.
        """
        if not sql_tuple:
            sql_tuple = (f'SELECT * FROM {self._table_name}',()) 

        async with self._aiosql_conn.execute(*sql_tuple) as cursor:
            async for row in cursor: yield row
    
    async def select_once(self, *, sql_tuple: Optional[tuple] = None) -> tuple:
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
        INSERT INTO TABLE_NAME values (...).

        This method doesn't check if you insert correct data
        or correct amount of it, you should know DB structure.
        """
        if not sql_statement:
            sql_statement = (
                f'INSERT INTO {self._table_name} values ('
                + ('?,' * len(args))[:-1] + ')'
            )
        await self._aiosql_conn.execute(sql_statement, args)
        if commit: await self._aiosql_conn.commit()
    
    async def execute(self, sql_tuple: tuple, commit: bool=True):
        result = await self._aiosql_conn.execute(*sql_tuple)
        if commit: await self._aiosql_conn.commit()
        return result # Returns Cursor object

    async def commit(self) -> None:
        await self._aiosql_conn.commit()

class TgboxDB:
    def __init__(self, db_path: Union[Path, str]):
        """
        Arguments:
            db_path (````Path````, ````str````):
                Path to the Tgbox DB.
        """
        if isinstance(db_path, Path):
            self._db_path = db_path
        else:
            self._db_path = Path(db_path)

        self._aiosql_db = None
        self._aiosql_db_is_closed = None
        self._name = self._db_path.name

        if self._db_path.is_dir():
            raise PathIsDirectory('Path is directory.')
    
    @property
    def name(self) -> str:
        return self._name

    @property
    def db_path(self) -> bool:
        return self._db_path
    
    @property
    def closed(self) -> bool:
        """
        This method will return ``None`` if DB wasn't opened,
        False if it's still opened, True if it's was closed.
        """
        return self._aiosql_db_is_closed
    
    @staticmethod
    async def create(db_path: Union[str, Path]) -> 'TgboxDB':
        return await TgboxDB(db_path).init()

    async def close(self) -> None:
        await self._aiosql_db.close()
        self._aiosql_db_is_closed = True
        self.BoxData = None
        self.Files = None
        self.Folders = None
    
    async def init(self) -> 'TgboxDB':
        self._aiosql_db = await aiosqlite.connect(self._db_path)
        await self._aiosql_db.execute(
            """CREATE TABLE IF NOT EXISTS BOX_DATA (LAST_FILE_ID int NOT NULL, """
            """BOX_CHANNEL_ID blob NOT NULL, BOX_CR_TIME blob NOT NULL, """
            """BOX_SALT blob NOT NULL, MAINKEY blob, SESSION blob NOT NULL);""" 
        )
        await self._aiosql_db.execute(
            """CREATE TABLE IF NOT EXISTS FILES (ID integer PRIMARY KEY, """
            """FOLDER_ID blob NOT NULL, COMMENT blob, DURATION blob NOT NULL, """
            """FILE_IV blob NOT NULL, FILE_KEY blob, FILE_NAME blob NOT NULL, """
            """FILE_SALT blob NOT NULL, PREVIEW blob, SIZE blob NOT NULL, """
            """UPLOAD_TIME blob NOT NULL, VERBYTE blob NOT NULL, FILE_PATH blob)"""
        )
        await self._aiosql_db.execute(
            """CREATE TABLE IF NOT EXISTS FOLDERS (FOLDER blob NOT NULL, """
            """FOLDER_IV blob NOT NULL, FOLDER_ID blob NOT NULL)"""
        )
        await self._aiosql_db.commit()
        self._aiosql_db_is_closed = False

        self.BoxData = SqlTableWrapper(self._aiosql_db,'BOX_DATA')
        self.Files = SqlTableWrapper(self._aiosql_db,'FILES')
        self.Folders = SqlTableWrapper(self._aiosql_db,'FOLDERS')

        return self
