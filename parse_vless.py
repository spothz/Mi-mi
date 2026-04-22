#!/usr/bin/env python3
import argparse
import base64
import re
import uuid
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

    if isinstance(data, list):
        return [Source(url=str(item)) for item in data]

    if not isinstance(data, dict):
        raise ValueError("Unsupported sources.yaml format")

    raw_sources = data.get("sources", [])
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
    if len(compact) < 40:
        return False
    if not BASE64_BODY_RE.match(compact):
        return False
    return len(compact) % 4 == 0


def decode_base64_blob(text: str) -> Optional[str]:
    compact = "".join(text.strip().split())
    try:
        decoded = base64.b64decode(compact + "===", validate=False)
        out = decoded.decode("utf-8", errors="ignore")
    except Exception:
        return None
    return out if "vless://" in out.lower() else None


def extract_links(text: str) -> List[str]:
    links = [link.rstrip(").,]\"'>") for link in VLESS_REGEX.findall(text)]

    decoded = decode_base64_blob(text) if looks_like_base64_blob(text) else None
    if decoded:
        links.extend([link.rstrip(").,]\"'>") for link in VLESS_REGEX.findall(decoded)])

    unique: List[str] = []
    seen = set()
    for link in links:
        if link in seen:
            continue
        seen.add(link)
        unique.append(link)
    return unique


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

    value = int(port)
    if value < 1 or value > 65535:
        raise ValueError("Port out of range")
    return host, value


def parse_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return None


def parse_vless_link(link: str) -> Optional[Dict[str, object]]:
    parsed = urlparse(link)
    if parsed.scheme.lower() != "vless":
        return None
    if "@" not in parsed.netloc:
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

    name = unquote(parsed.fragment or "").strip()
    if not name:
        name = f"vless-{host}:{port}"

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

    allow_insecure = parse_bool(get_param("allowInsecure", "allowinsecure"))
    if allow_insecure is not None:
        proxy["skip-cert-verify"] = allow_insecure

    servername = get_param("sni", "servername", "peer")
    if servername:
        proxy["servername"] = servername

    alpn = get_param("alpn")
    if alpn:
        proxy["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]

    fingerprint = get_param("fp", "fingerprint")
    if fingerprint:
        proxy["client-fingerprint"] = fingerprint

    flow = get_param("flow")
    if flow:
        proxy["flow"] = flow

    if security == "reality":
        reality_opts: Dict[str, object] = {}
        if pbk := get_param("pbk", "publicKey"):
            reality_opts["public-key"] = pbk
        if short_id := get_param("sid", "shortId"):
            reality_opts["short-id"] = short_id
        if spider_x := get_param("spx", "spiderX"):
            reality_opts["spider-x"] = spider_x
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
        multi_mode = parse_bool(get_param("mode"))
        if multi_mode is not None:
            grpc_opts["grpc-mode"] = "multi" if multi_mode else "gun"
        if grpc_opts:
            proxy["grpc-opts"] = grpc_opts

    if network in {"http", "h2"}:
        h2_opts: Dict[str, object] = {}
        if path := get_param("path"):
            h2_opts["path"] = path
        if host_header := get_param("host"):
            h2_opts["host"] = [item.strip() for item in host_header.split(",") if item.strip()]
        if h2_opts:
            proxy["h2-opts"] = h2_opts

    return proxy


def dedupe_proxies(proxies: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    seen = set()
    unique: List[Dict[str, object]] = []
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
        unique.append(proxy)
    return unique


def ensure_unique_names(proxies: List[Dict[str, object]]) -> None:
    counts: Dict[str, int] = {}
    for proxy in proxies:
        name = str(proxy.get("name"))
        counts[name] = counts.get(name, 0) + 1
        if counts[name] > 1:
            proxy["name"] = f"{name}-{counts[name]}"


def build_output(proxies: List[Dict[str, object]]) -> Dict[str, object]:
    return {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "count": len(proxies),
        },
        "proxies": proxies,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse VLESS links from public sources and export Clash YAML."
    )
    parser.add_argument(
        "--sources",
        type=Path,
        default=Path("sources.yaml"),
        help="Path to YAML with source URLs.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("proxies.yaml"),
        help="Output YAML file for Clash proxies section.",
    )
    args = parser.parse_args()

    sources = load_sources(args.sources)
    if not sources:
        raise SystemExit("No sources found in sources.yaml")

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) parser/2.0"})

    all_links: List[str] = []
    for source in sources:
        try:
            content = fetch_url(source.url, session=session)
            links = extract_links(content)
            print(f"[ok] {source.url} ({source.tag}) -> {len(links)} links")
            all_links.extend(links)
        except Exception as exc:
            print(f"[warn] {source.url} ({source.tag}): {exc}")

    proxies: List[Dict[str, object]] = []
    for link in all_links:
        try:
            proxy = parse_vless_link(link)
        except Exception:
            proxy = None
        if proxy:
            proxies.append(proxy)

    proxies = dedupe_proxies(proxies)
    ensure_unique_names(proxies)

    output = build_output(proxies)
    args.output.write_text(
        yaml.safe_dump(output, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    print(f"[done] wrote {len(proxies)} proxies to {args.output}")


if __name__ == "__main__":
    main()
