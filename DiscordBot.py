import discord
from discord.ext import commands
import os
import asyncio
import socket
import ipaddress
from dotenv import load_dotenv
from typing import Tuple, Optional

load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

# -----------------------
# Helpers
# -----------------------
async def tcp_connect_latency(host: str, port: int, timeout: float = 2.0) -> Tuple[bool, Optional[float], Optional[str]]:
    """
    Attempt a TCP connect to host:port (supports hostnames and IPs, IPv4/IPv6).
    Returns (success, latency_ms or None, resolved_ip or None).
    Non-blocking-ish: uses getaddrinfo and run_in_executor for connect.
    """
    loop = asyncio.get_running_loop()
    start = loop.time()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception:
        return False, None, None

    for family, socktype, proto, canonname, sockaddr in infos:
        ip = sockaddr[0]
        s = None
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(timeout)
            # run blocking connect in executor
            await loop.run_in_executor(None, s.connect, sockaddr)
            s.close()
            latency_ms = (loop.time() - start) * 1000.0
            return True, latency_ms, ip
        except Exception:
            try:
                if s:
                    s.close()
            except Exception:
                pass
            continue
    return False, None, None

def simple_whois_query_blocking(domain: str, timeout: int = 5) -> str:
    """
    Blocking WHOIS lookup that queries IANA for the whois server, then queries that server.
    Returns text (may be long).
    """
    domain = domain.strip()
    if not domain:
        return "Empty domain."
    query = domain + "\r\n"
    try:
        # ask IANA for whois server
        with socket.create_connection(("whois.iana.org", 43), timeout=timeout) as s:
            s.sendall(query.encode())
            resp = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                resp += data
            iana_text = resp.decode(errors="ignore")

        # find whois server in IANA response
        whois_server = None
        for line in iana_text.splitlines():
            if line.lower().startswith("whois:"):
                whois_server = line.split(":", 1)[1].strip()
                break
        if not whois_server:
            # fallback
            whois_server = "whois.arin.net"

        with socket.create_connection((whois_server, 43), timeout=timeout) as s:
            s.sendall(query.encode())
            resp = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                resp += data
            return resp.decode(errors="ignore")
    except Exception as e:
        return f"WHOIS error: {type(e).__name__}: {e}"

# -----------------------
# Commands
# -----------------------

@bot.command(name="ping")
async def cmd_ping(ctx, target: str, port: int = None):
    """
    Usage:
      !ping <host_or_ip> [port]
    Tries common ports (80,443,53,22) unless a specific port is provided.
    Supports IPv4 and IPv6.
    """
    await ctx.send(f"Pinging `{target}`...")

    # If user provided a port, try only that; otherwise try common ports
    if port:
        ports_to_try = [port]
    else:
        ports_to_try = [80, 443, 53, 22]

    timeout = 2.0
    # First try the name/ip directly with each port
    for p in ports_to_try:
        ok, latency, ip = await tcp_connect_latency(target, p, timeout=timeout)
        if ok:
            await ctx.send(f"✅ `{target}` ({ip}) reachable on port `{p}` — {latency:.1f} ms")
            return

    # If target is not a literal IP, attempt to resolve to IPs and try those (sometimes CNAMEs)
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except Exception:
        is_ip = False

    if not is_ip:
        try:
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(target, None)
            resolved_ips = []
            for fam, st, pr, cn, sa in infos:
                resolved_ips.append(sa[0])
            resolved_ips = list(dict.fromkeys(resolved_ips))  # unique preserve order
            for ip in resolved_ips:
                for p in ports_to_try:
                    ok, latency, resolved_ip = await tcp_connect_latency(ip, p, timeout=timeout)
                    if ok:
                        await ctx.send(f"✅ `{target}` resolved to `{resolved_ip}` and is reachable on port `{p}` — {latency:.1f} ms")
                        return
        except Exception:
            pass

    await ctx.send(f"❌ `{target}` not reachable on tried ports `{ports_to_try}`. (Some hosts block TCP or only respond to ICMP.)")

@bot.command(name="whois")
async def cmd_whois(ctx, domain: str):
    """
    Usage:
      !whois example.com
    Performs a basic public WHOIS lookup (blocking work runs in executor).
    """
    await ctx.defer()  # give the bot more time if lookup is slow
    loop = asyncio.get_running_loop()
    raw = await loop.run_in_executor(None, simple_whois_query_blocking, domain)
    # truncate if too long
    if len(raw) > 1900:
        raw = raw[:1890] + "\n...truncated..."
    await ctx.send(f"WHOIS for `{domain}`:\n```\n{raw}\n```")

# Keep your homeports scanner (optional)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 161, 443, 445, 993, 995,
    3306, 3389, 5900, 8080, 25565, 32400
]

async def scan_port(host, port, semaphore):
    async with semaphore:
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(0.6)
            result = conn.connect_ex((host, port))
            conn.close()
            return port, result == 0
        except:
            return port, False

@bot.command(name="homeports")
async def cmd_homeports(ctx, host: str):
    """Scan common home ports"""
    await ctx.defer()
    semaphore = asyncio.Semaphore(12)
    tasks = [scan_port(host, port, semaphore) for port in COMMON_PORTS]
    results = await asyncio.gather(*tasks)

    lines = []
    open_count = 0
    for port, is_open in results:
        if is_open:
            open_count += 1
            lines.append(f"`{port}` — **OPEN**")
        else:
            lines.append(f"`{port}` — closed")
    out = f"Home port scan for `{host}` — {open_count} open ports:\n" + "\n".join(lines)
    if len(out) > 2000:
        out = out[:1990] + "\n...truncated..."
    await ctx.send(out)

# -----------------------
# Events & run
# -----------------------
@bot.event
async def on_ready():
    print(f"Bot ready: {bot.user} (id: {bot.user.id})")

if not DISCORD_TOKEN:
    print("WARN: DISCORD_TOKEN is not set in environment.")
else:
    bot.run(DISCORD_TOKEN)
