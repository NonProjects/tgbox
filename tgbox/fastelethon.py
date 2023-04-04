"""
Copied from Mautrix-Telegram
    github.com/tulir/mautrix-telegram/

Copied again from Painor GitHub
    gist.github.com/painor/7e74de80ae0c819d3e9abcf9989a8dd6

| This file was patched for TGBOX project (github.com/NonProjects/tgbox)
| and may not work as you expect in your code.

Big thanks to all contributors of this module.
"""

import os
import math
import asyncio
import hashlib
import inspect
import logging

from typing import (
    Optional, List, AsyncGenerator,
    Union, Awaitable, BinaryIO,
    DefaultDict, Tuple
)
from collections import defaultdict

from telethon.tl.functions.auth import (
    ExportAuthorizationRequest,
    ImportAuthorizationRequest
)
from telethon.errors import FilePartsInvalidError
from telethon import utils, helpers, TelegramClient
from telethon.tl.custom.file import File

from telethon.crypto import AuthKey
from telethon.network import MTProtoSender

from telethon.tl.alltlobjects import LAYER
from telethon.tl.functions import InvokeWithLayerRequest

from telethon.tl.types import (
    Document, InputFileLocation,
    InputDocumentFileLocation,
    InputPhotoFileLocation,
    InputPeerPhotoFileLocation,
    TypeInputFile, Photo,
    InputFileBig, InputFile
)
from telethon.tl.functions.upload import (
    GetFileRequest,
    SaveFilePartRequest,
    SaveBigFilePartRequest
)
logger: logging.Logger = logging.getLogger(__name__)

TypeLocation = Union[
    Document, Photo, InputDocumentFileLocation,
    InputPeerPhotoFileLocation,
    InputFileLocation, InputPhotoFileLocation
]
class DownloadSender:
    client: TelegramClient
    sender: MTProtoSender
    request: GetFileRequest
    remaining: int
    stride: int

    def __init__(
            self, client: TelegramClient,
            sender: MTProtoSender,
            file: TypeLocation,
            offset: int, limit: int,
            stride: int, count: int) -> None:

        # TODO: Add left bytes to buffer and return.
        self.offset = offset
        # Offset must be divisible by 4096, otherwise
        # error. We concat left bytes later.
        self.safe_offset = offset - offset % 4096

        self.sender = sender
        self.client = client
        self.stride = stride
        self.remaining = count

        self.request = GetFileRequest(
            file, offset=self.safe_offset, limit=limit
        )

    async def next(self) -> Optional[bytes]:
        if not self.remaining:
            return None

        result = await self.client._call(self.sender, self.request)

        self.remaining -= 1
        self.request.offset += self.stride

        result_bytes = result.bytes[self.offset - self.safe_offset:]
        return result_bytes

    def disconnect(self) -> Awaitable[None]:
        return self.sender.disconnect()


class UploadSender:
    client: TelegramClient
    sender: MTProtoSender
    request: Union[SaveFilePartRequest, SaveBigFilePartRequest]
    part_count: int
    stride: int
    previous: Optional[asyncio.Task]
    loop: asyncio.AbstractEventLoop

    def __init__(self, client: TelegramClient, sender: MTProtoSender, file_id: int, part_count: int, big: bool,
                 index: int,
                 stride: int, loop: asyncio.AbstractEventLoop) -> None:
        self.client = client
        self.sender = sender
        self.part_count = part_count
        if big:
            self.request = SaveBigFilePartRequest(file_id, index, part_count, b"")
        else:
            self.request = SaveFilePartRequest(file_id, index, b"")
        self.stride = stride
        self.previous = None
        self.loop = loop

    async def next(self, data: bytes) -> None:
        if self.previous:
            await self.previous
        self.previous = self.loop.create_task(self._next(data))

    async def _next(self, data: bytes) -> None:
        self.request.bytes = data
        logger.debug(f"Sending file part {self.request.file_part}/{self.part_count}"
                  f" with {len(data)} bytes")
        await self.client._call(self.sender, self.request)
        self.request.file_part += self.stride

    async def disconnect(self) -> None:
        if self.previous:
            await self.previous
        return await self.sender.disconnect()


class ParallelTransferrer:
    client: TelegramClient
    loop: asyncio.AbstractEventLoop
    dc_id: int
    senders: Optional[List[Union[DownloadSender, UploadSender]]]
    auth_key: AuthKey
    upload_ticker: int

    def __init__(self, client: TelegramClient, dc_id: Optional[int] = None) -> None:
        self.client = client
        self.loop = self.client.loop
        self.dc_id = dc_id or self.client.session.dc_id
        self.auth_key = (None if dc_id and self.client.session.dc_id != dc_id
                         else self.client.session.auth_key)
        self.senders = None
        self.upload_ticker = 0

    async def _cleanup(self) -> None:
        try:
            await asyncio.gather(*[sender.disconnect() for sender in self.senders])
        except FilePartsInvalidError:
            pass
        self.senders = None

    @staticmethod
    def _get_connection_count(file_size: int, max_count: int = 20,
                              full_size: int = 100 * 1024 * 1024) -> int:
        if file_size > full_size:
            return max_count
        return math.ceil((file_size / full_size) * max_count)

    async def _init_download(
            self, connections: int,
            file: TypeLocation,
            part_count: int,
            part_size: int,
            offset: int) -> None:

        minimum, remainder = divmod(part_count, connections)

        def get_part_count() -> int:
            nonlocal remainder
            if remainder > 0:
                remainder -= 1
                return minimum + 1
            return minimum

        # The first cross-DC sender will export+import the authorization, so
        # we always create it before creating any other senders.
        self.senders = [
            await self._create_download_sender(
                file, 0, part_size, connections * part_size,
                get_part_count(), offset=offset
            ),
            *await asyncio.gather(
                *[
                    self._create_download_sender(
                        file, i, part_size,
                        connections * part_size,
                        get_part_count(),
                        offset=offset
                    )
                    for i in range(1, connections)
                ])
        ]
    async def _create_download_sender(
            self, file: TypeLocation,
            index: int,
            part_size: int,
            stride: int,
            part_count: int,
            offset: int = None) -> DownloadSender:

        offset = offset if offset else index * part_size

        return DownloadSender(
            self.client,
            await self._create_sender(),
            file, offset, part_size,
            stride, part_count
        )

    async def _init_upload(self, connections: int, file_id: int, part_count: int, big: bool
                           ) -> None:
        self.senders = [
            await self._create_upload_sender(file_id, part_count, big, 0, connections),
            *await asyncio.gather(
                *[self._create_upload_sender(file_id, part_count, big, i, connections)
                  for i in range(1, connections)])
        ]

    async def _create_upload_sender(self, file_id: int, part_count: int, big: bool, index: int,
                                    stride: int) -> UploadSender:
        return UploadSender(self.client, await self._create_sender(), file_id, part_count, big, index, stride,
                            loop=self.loop)

    async def _create_sender(self) -> MTProtoSender:
        dc = await self.client._get_dc(self.dc_id)
        sender = MTProtoSender(self.auth_key, loggers=self.client._log)
        await sender.connect(self.client._connection(dc.ip_address, dc.port, dc.id,
                                                     loggers=self.client._log,
                                                     proxy=self.client._proxy))
        if not self.auth_key:
            logger.debug(f"Exporting auth to DC {self.dc_id}")
            auth = await self.client(ExportAuthorizationRequest(self.dc_id))
            self.client._init_request.query = ImportAuthorizationRequest(id=auth.id,
                                                                         bytes=auth.bytes)
            req = InvokeWithLayerRequest(LAYER, self.client._init_request)
            await sender.send(req)
            self.auth_key = sender.auth_key
        return sender

    async def init_upload(self, file_id: int, file_size: int, part_size_kb: Optional[float] = None,
                          connection_count: Optional[int] = None) -> Tuple[int, int, bool]:
        connection_count = connection_count or self._get_connection_count(file_size)
        part_size = (part_size_kb or utils.get_appropriated_part_size(file_size)) * 1024
        part_count = (file_size + part_size - 1) // part_size
        is_large = file_size > 10 * 1024 * 1024
        await self._init_upload(connection_count, file_id, part_count, is_large)
        return part_size, part_count, is_large

    async def upload(self, part: bytes) -> None:
        await self.senders[self.upload_ticker].next(part)
        self.upload_ticker = (self.upload_ticker + 1) % len(self.senders)

    async def finish_upload(self) -> None:
        await self._cleanup()

    async def download(
            self, file: TypeLocation, file_size: int,
            part_size_kb: Optional[int] = None,
            offset: Optional[int] = None,
            connection_count: Optional[int] = None
            ) -> AsyncGenerator[bytes, None]:

        connection_count = connection_count or self._get_connection_count(file_size)
        part_size = (part_size_kb or utils.get_appropriated_part_size(file_size)) * 1024
        part_count = math.ceil(file_size / part_size)

        logger.debug("Starting parallel download: "
                  f"{connection_count} {part_size} {part_count} {file!s}")

        await self._init_download(
            connection_count,
            file, part_count,
            part_size, offset=offset
        )
        part = 0
        while part < part_count:
            tasks = []
            for sender in self.senders:
                tasks.append(self.loop.create_task(sender.next()))
            for task in tasks:
                data = await task
                if not data:
                    break
                yield data
                part += 1
                logger.debug(f"Part {part} downloaded")

        logger.debug("Parallel download finished, cleaning up connections")
        await self._cleanup()


parallel_transfer_locks: DefaultDict[int, asyncio.Lock] =\
    defaultdict(lambda: asyncio.Lock())

async def stream_file(
        file_to_stream: BinaryIO,
        chunk_size = 1024
    ):
    """``file_to_stream.read`` can be coroutine."""
    while True:
        data_read = file_to_stream.read(chunk_size)

        if inspect.iscoroutine(data_read):
            data_read = await data_read

        if data_read:
            yield data_read
        else:
            break

async def _internal_transfer_to_telegram(
        client: TelegramClient,
        response: BinaryIO,
        progress_callback: callable,
        file_size: int = None,
        file_name: str = 'document',
        part_size_kb: int = 512,
    ) -> Tuple[TypeInputFile, int]:

    file_id = helpers.generate_random_long()

    if not file_size:
        file_size = os.path.getsize(response.name)

    hash_md5 = hashlib.md5()
    uploader = ParallelTransferrer(client)

    part_size_, part_count, is_large =\
        await uploader.init_upload(
            file_id, file_size,
            part_size_kb=part_size_kb
        )
    if not part_size_kb:
        part_size = part_size_
    else:
        part_size = part_size_kb*1024

    buffer = bytearray()
    async for data in stream_file(response, part_size):
        if progress_callback:
            r = progress_callback(response.tell(), file_size)
            if inspect.isawaitable(r):
                await r

        if not is_large:
            hash_md5.update(data)

        if len(buffer) == 0 and len(data) == part_size:
            try:
                await uploader.upload(data)
                continue
            except FilePartsInvalidError as e:
                await uploader.finish_upload()
                raise e from None

        new_len = len(buffer) + len(data)
        if new_len >= part_size:
            cutoff = part_size - len(buffer)
            buffer.extend(data[:cutoff])

            await uploader.upload(bytes(buffer))

            buffer.clear()
            buffer.extend(data[cutoff:])
        else:
            buffer.extend(data)

    if len(buffer) > 0:
        await uploader.upload(bytes(buffer))

    await uploader.finish_upload()

    if is_large:
        return (InputFileBig(file_id, part_count, file_name), file_size)
    else:
        return (InputFile(file_id, part_count, file_name, hash_md5.hexdigest()), file_size)

async def download_file(
        client: TelegramClient,
        location: TypeLocation,
        request_size: int=524288,
        offset: int=None,
        progress_callback: callable = None
        ) -> AsyncGenerator[bytes, None]:

    if isinstance(location, Photo):
        size = File(location).size
    else:
        size = location.size

    dc_id, location = utils.get_input_location(location)

    # We lock the transfers because telegram has connection count limits
    downloader = ParallelTransferrer(client, dc_id)

    downloaded = downloader.download(
        location, size, offset=offset,
        part_size_kb=int(request_size/1024)
    )
    position = 0
    async for chunk in downloaded:
        position += len(chunk)
        if progress_callback:
            r = progress_callback(position, size)
            if inspect.isawaitable(r):
                await r
        yield chunk


async def upload_file(
        client: TelegramClient,
        file: BinaryIO,
        progress_callback: callable = None,
        file_name: str = 'document',
        file_size: int = None,
        part_size_kb: int = 512
        ) -> TypeInputFile:

    return (await _internal_transfer_to_telegram(
        client, file, progress_callback,
        file_size = file_size,
        file_name = file_name,
        part_size_kb = part_size_kb
        ))[0]
