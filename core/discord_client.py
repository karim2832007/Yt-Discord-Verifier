import discord
from discord.ext import commands
from dotenv import load_dotenv
import os

load_dotenv()

BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
GUILD_ID = int(os.getenv("DISCORD_GUILD_ID"))

intents = discord.Intents.default()
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents)

bot.remove_command("help")
