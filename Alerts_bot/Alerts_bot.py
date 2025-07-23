import re, os, asyncio
from aiogram import Bot, dispatcher, types, Dispatcher

token = ""  #<--- your token bot that you got from BotFather
chat_id = ""  #<--- your chat id
log = ""  #<--- your path to "fast_log.json" with alerts

bot = Bot(token=token)


async def alerts_atf():
    with open(log, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.5)
                continue

            if "[ALERT]" in line:
                text = f"'''\n{line.rstrip()}'''"
                await bot.send_message(chat_id, text, parse_mode="Markdown")




if __name__ == "__main__":
    asyncio.run(alerts_atf())
