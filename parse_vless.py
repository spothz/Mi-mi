#!/usr/bin/env python3
import argparse
import base64
import ipaddress
import re
import socket
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import requests
import yaml

VLESS_REGEX = re.compile(r"vless://[^\s'\"<>]+", re.IGNORECASE)
BASE64_BODY_RE = re.compile(r"^[A-Za-z0-9+/=_\s-]{40,}$")


@dataclass
class Source:
    url: str
    tag: str = "generic"


def load_sources(path: Path) -> List[Source]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw_sources = data if isinstance(data, list) else data.get("sources", [])

    sources: List[Source] = []
    for item in raw_sources:
        if isinstance(item, str):
            sources.append(Source(url=item))
        elif isinstance(item, dict) and item.get("url"):
            sources.append(Source(url=str(item["url"]), tag=str(item.get("tag") or "generic")))
    return sources


def fetch_url(url: str, session: requests.Session, timeout: int = 20) -> str:
    response = session.get(url, timeout=timeout, allow_redirects=True)
    response.raise_for_status()
    response.encoding = response.encoding or "utf-8"
    return response.text


def looks_like_base64_blob(text: str) -> bool:
    compact = "".join(text.strip().split())
    return bool(len(compact) >= 40 and len(compact) % 4 == 0 and BASE64_BODY_RE.match(compact))


def decode_base64_blob(text: str) -> Optional[str]:
    compact = "".join(text.strip().split())
    try:
        decoded = base64.b64decode(compact + "===", validate=False).decode("utf-8", errors="ignore")
    except Exception:
        return None
    return decoded if "vless://" in decoded.lower() else None


def extract_links(text: str) -> List[str]:
    links = [link.rstrip(").,]\"'>") for link in VLESS_REGEX.findall(text)]

    # whole body base64
    if looks_like_base64_blob(text):
        decoded = decode_base64_blob(text)
        if decoded:
            links.extend([link.rstrip(").,]\"'>") for link in VLESS_REGEX.findall(decoded)])

    # line-based base64 subscriptions
    for line in text.splitlines():
        clean = line.strip()
        if looks_like_base64_blob(clean):
            decoded = decode_base64_blob(clean)
            if decoded:
                links.extend([link.rstrip(").,]\"'>") for link in VLESS_REGEX.findall(decoded)])

    return list(dict.fromkeys(links))


def split_host_port(hostport: str) -> Tuple[str, int]:
    host = hostport
    port: Optional[str] = None

    if hostport.startswith("[") and "]" in hostport:
        end = hostport.index("]")
        host = hostport[1:end]
        rest = hostport[end + 1 :]
        if rest.startswith(":"):
            port = rest[1:]
    elif ":" in hostport:
        host, port = hostport.rsplit(":", 1)

    if port is None:
        raise ValueError("Missing port")

    port_int = int(port)
    if not (1 <= port_int <= 65535):
        raise ValueError("Port out of range")

    return host, port_int


def parse_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return None


def parse_vless_link(link: str) -> Optional[Dict[str, object]]:
    parsed = urlparse(link)
    if parsed.scheme.lower() != "vless" or "@" not in parsed.netloc:
        return None

    raw_uuid, hostport = parsed.netloc.split("@", 1)
    try:
        user_uuid = str(uuid.UUID(raw_uuid.strip()))
    except Exception:
        return None

    host, port = split_host_port(hostport)
    params = parse_qs(parsed.query)

    def get_param(*keys: str) -> Optional[str]:
        for key in keys:
            values = params.get(key)
            if values and values[0] != "":
                return unquote(values[0]).strip()
        return None

    security = (get_param("security") or "none").lower()
    network = (get_param("type", "network") or "tcp").lower()
    cipher = (get_param("encryption") or "none").lower()

    name = unquote(parsed.fragment or "").strip() or f"vless-{host}:{port}"

    proxy: Dict[str, object] = {
        "name": name,
        "type": "vless",
        "server": host,
        "port": port,
        "uuid": user_uuid,
        "cipher": cipher,
        "udp": True,
        "network": network,
    }

    if security in {"tls", "xtls", "reality"}:
        proxy["tls"] = True

    insecure = parse_bool(get_param("allowInsecure", "allowinsecure"))
    if insecure is not None:
        proxy["skip-cert-verify"] = insecure

    if servername := get_param("sni", "servername", "peer"):
        proxy["servername"] = servername

    if alpn := get_param("alpn"):
        proxy["alpn"] = [p.strip() for p in alpn.split(",") if p.strip()]

    if flow := get_param("flow"):
        proxy["flow"] = flow

    if fp := get_param("fp", "fingerprint"):
        proxy["client-fingerprint"] = fp

    if security == "reality":
        reality_opts: Dict[str, object] = {}
        if pbk := get_param("pbk", "publicKey"):
            reality_opts["public-key"] = pbk
        if sid := get_param("sid", "shortId"):
            reality_opts["short-id"] = sid
        if spx := get_param("spx", "spiderX"):
            reality_opts["spider-x"] = spx
        if reality_opts:
            proxy["reality-opts"] = reality_opts

    if network == "ws":
        ws_opts: Dict[str, object] = {}
        if path := get_param("path"):
            ws_opts["path"] = path
        if host_header := get_param("host"):
            ws_opts["headers"] = {"Host": host_header}
        if ws_opts:
            proxy["ws-opts"] = ws_opts

    if network == "grpc":
        grpc_opts: Dict[str, object] = {}
        if service_name := get_param("serviceName", "service_name"):
            grpc_opts["grpc-service-name"] = service_name
        if grpc_opts:
            proxy["grpc-opts"] = grpc_opts

    if network in {"h2", "http"}:
        h2_opts: Dict[str, object] = {}
        if path := get_param("path"):
            h2_opts["path"] = path
        if host_header := get_param("host"):
            h2_opts["host"] = [item.strip() for item in host_header.split(",") if item.strip()]
        if h2_opts:
            proxy["h2-opts"] = h2_opts

    return proxy


def dedupe_proxies(proxies: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    out: List[Dict[str, object]] = []
    seen = set()
    for proxy in proxies:
        key = (
            proxy.get("server"),
            proxy.get("port"),
            proxy.get("uuid"),
            proxy.get("network"),
            proxy.get("flow"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(proxy)
    return out


def ensure_unique_names(proxies: List[Dict[str, object]]) -> None:
    counts: Dict[str, int] = {}
    for proxy in proxies:
        name = str(proxy.get("name"))
        counts[name] = counts.get(name, 0) + 1
        if counts[name] > 1:
            proxy["name"] = f"{name}-{counts[name]}"


def tcp_check(host: str, port: int, timeout: float = 2.5) -> Tuple[bool, Optional[int]]:
    start = datetime.now(timezone.utc)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            end = datetime.now(timezone.utc)
            ms = int((end - start).total_seconds() * 1000)
            return True, ms
    except Exception:
        return False, None


def resolve_ip(host: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(host))
    except Exception:
        pass

    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except Exception:
        return None
    return None


def country_for_host(host: str, session: requests.Session, cache: Dict[str, str]) -> str:
    ip = resolve_ip(host)
    if not ip:
        return "ZZ"
    if ip in cache:
        return cache[ip]

    try:
        r = session.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,countryCode"},
            timeout=8,
        )
        r.raise_for_status()
        data = r.json()
        cc = str(data.get("countryCode") or "ZZ").upper()
    except Exception:
        cc = "ZZ"

    if not re.match(r"^[A-Z]{2}$", cc):
        cc = "ZZ"

    cache[ip] = cc
    return cc


def build_output(proxies: List[Dict[str, object]]) -> Dict[str, object]:
    return {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "count": len(proxies),
        },
        "proxies": proxies,
    }


def write_country_files(output_dir: Path, grouped: Dict[str, List[Dict[str, object]]]) -> None:
    country_dir = output_dir / "countries"
    country_dir.mkdir(parents=True, exist_ok=True)
    for country in sorted(grouped):
        payload = build_output(grouped[country])
        (country_dir / f"{country}.yaml").write_text(
            yaml.safe_dump(payload, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse and validate public VLESS nodes.")
    parser.add_argument("--sources", type=Path, default=Path("sources.yaml"))
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    parser.add_argument("--output", type=str, default="all.yaml")
    parser.add_argument("--check", action="store_true", help="TCP-check every parsed node")
    parser.add_argument("--split-by-country", action="store_true", help="Write countries/*.yaml")
    args = parser.parse_args()

    sources = load_sources(args.sources)
    if not sources:
        raise SystemExit("No sources found")

    http = requests.Session()
    http.headers.update({"User-Agent": "Mozilla/5.0 parser/3.0"})

    all_links: List[str] = []
    for source in sources:
        try:
            body = fetch_url(source.url, http)
            links = extract_links(body)
            print(f"[ok] {source.url} ({source.tag}) -> {len(links)}")
            all_links.extend(links)
        except Exception as exc:
            print(f"[warn] {source.url}: {exc}")

    all_links = list(dict.fromkeys(all_links))
    proxies = [proxy for link in all_links if (proxy := parse_vless_link(link))]
    proxies = dedupe_proxies(proxies)

    alive: List[Dict[str, object]] = []
    for proxy in proxies:
        if not args.check:
            alive.append(proxy)
            continue
        ok, latency = tcp_check(str(proxy["server"]), int(proxy["port"]))
        if ok:
            proxy["latency"] = latency
            alive.append(proxy)

    if args.check:
        print(f"[info] alive after check: {len(alive)}/{len(proxies)}")

    cc_cache: Dict[str, str] = {}
    grouped: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for proxy in alive:
        cc = country_for_host(str(proxy["server"]), http, cc_cache)
        proxy["country"] = cc
        grouped[cc].append(proxy)

    for cc in grouped:
        ensure_unique_names(grouped[cc])

    final_proxies: List[Dict[str, object]] = []
    for cc in sorted(grouped):
        final_proxies.extend(grouped[cc])

    args.output_dir.mkdir(parents=True, exist_ok=True)
    output_file = args.output_dir / args.output
    output_file.write_text(
        yaml.safe_dump(build_output(final_proxies), allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )

    if args.split_by_country:
        write_country_files(args.output_dir, grouped)

    (args.output_dir / "links.txt").write_text("\n".join(all_links), encoding="utf-8")
    print(f"[done] parsed={len(proxies)} alive={len(final_proxies)} file={output_file}")


if __name__ == "__main__":
    main()
