from __future__ import annotations

import asyncio
import getpass
from telethon import TelegramClient
from telethon.sessions import StringSession


async def main() -> None:
    api_id = int(input("Telegram API ID: ").strip())
    api_hash = getpass.getpass("Telegram API hash: ").strip()
    async with TelegramClient(StringSession(), api_id, api_hash) as client:
        session = client.session.save()
    print("\nSession generated. Treat it like a password.")
    print("Store it as TELEGRAM_STRING_SESSION in Railway:\n")
    print(session)


if __name__ == "__main__":
    asyncio.run(main())
