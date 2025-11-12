import discord
from discord.ext import commands
import os
import asyncio
import socket

# Load token from .env
from dotenv import load_dotenv
load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")

# Bot setup
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# ----- Ping command using TCP -----
@bot.command()
async def ping(ctx, host: str):
    """Ping a host using a TCP connection (no system ping needed)"""
    await ctx.send(f"Pinging {host}...")

    ports_to_try = [80, 443]  # common HTTP/HTTPS ports
    reachable = False

    for port in ports_to_try:
        try:
            conn = socket.create_connection((host, port), timeout=2)
            conn.close()
            reachable = True
            await ctx.send(f"{host} is reachable on port {port}!")
            break
        except Exception:
            continue

    if not reachable:
        await ctx.send(f"{host} is not reachable on common ports.")

# ----- Home ports scanner -----
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 80, 110,
    123, 135, 137, 138, 139, 143, 161, 162,
    443, 445, 993, 995, 3306, 3389, 5900, 8080
]

async def scan_port(host, port, semaphore):
    async with semaphore:
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(0.5)
            result = conn.connect_ex((host, port))
            conn.close()
            return port, result == 0
        except:
            return port, False

@bot.command()
async def homeports(ctx, host: str):
    """Scan common home ports"""
    await ctx.send(f"Scanning common ports on {host}...")
    semaphore = asyncio.Semaphore(8)  # limit concurrency
    tasks = [scan_port(host, port, semaphore) for port in COMMON_PORTS]
    results = await asyncio.gather(*tasks)

    msg = f"Port scan results for {host}:\n"
    for port, is_open in results:
        status = "OPEN" if is_open else "closed"
        msg += f"{port}: {status}\n"

    # Send message in chunks if too long
    for chunk in [msg[i:i+2000] for i in range(0, len(msg), 2000)]:
        await ctx.send(f"```\n{chunk}\n```")

# ----- Bot ready event -----
@bot.event
async def on_ready():
    print(f"Bot ready: {bot.user} (id: {bot.user.id})")

# ----- Run bot -----
bot.run(DISCORD_TOKEN)
