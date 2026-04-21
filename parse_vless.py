#!/usr/bin/env python3
import argparse
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import requests
import yaml

VLESS_REGEX = re.compile(r"vless://[^\s'\"]+")


def load_sources(path: Path) -> List[str]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if isinstance(data, list):
        return [str(item) for item in data]
    if isinstance(data, dict):
        sources = data.get("sources", [])
        return [str(item) for item in sources]
    raise ValueError("Unsupported sources.yaml format")


def fetch_url(url: str, timeout: int = 15) -> str:
    response = requests.get(
        url,
        timeout=timeout,
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
    )
    response.raise_for_status()
    return response.text


def extract_links(text: str) -> List[str]:
    return [link.rstrip(").,]") for link in VLESS_REGEX.findall(text)]


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
    return host, int(port)


def parse_vless_link(link: str) -> Optional[Dict[str, object]]:
    parsed = urlparse(link)
    if parsed.scheme != "vless":
        return None
    if "@" not in parsed.netloc:
        return None
    uuid, hostport = parsed.netloc.split("@", 1)
    host, port = split_host_port(hostport)

    params = parse_qs(parsed.query)
    get_param = lambda key: (params.get(key) or [None])[0]

    name = unquote(parsed.fragment) if parsed.fragment else f"vless-{host}:{port}"
    name = name.strip() or f"vless-{host}:{port}"

    security = (get_param("security") or "").lower()
    network = (get_param("type") or get_param("network") or "tcp").lower()
    cipher = (get_param("encryption") or "none").lower()
    allow_insecure = get_param("allowInsecure") or get_param("allowinsecure")

    proxy: Dict[str, object] = {
        "name": name,
        "type": "vless",
        "server": host,
        "port": port,
        "uuid": uuid,
        "udp": True,
        "cipher": cipher,
        "network": network,
    }

    if security in {"tls", "reality", "xtls"}:
        proxy["tls"] = True

    if allow_insecure is not None:
        proxy["skip-cert-verify"] = allow_insecure in {"1", "true", "yes"}

    sni = get_param("sni") or get_param("peer")
    if sni:
        proxy["servername"] = sni

    alpn = get_param("alpn")
    if alpn:
        proxy["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]

    fingerprint = get_param("fp")
    if fingerprint:
        proxy["fingerprint"] = fingerprint

    flow = get_param("flow")
    if flow:
        proxy["flow"] = flow

    if security == "reality":
        reality_opts = {}
        public_key = get_param("pbk") or get_param("publicKey")
        short_id = get_param("sid") or get_param("shortId")
        spider_x = get_param("spx") or get_param("spiderX")
        if public_key:
            reality_opts["public-key"] = public_key
        if short_id:
            reality_opts["short-id"] = short_id
        if spider_x:
            reality_opts["spider-x"] = spider_x
        if reality_opts:
            proxy["reality-opts"] = reality_opts

    if network == "ws":
        ws_opts: Dict[str, object] = {}
        path = get_param("path")
        if path:
            ws_opts["path"] = unquote(path)
        host_header = get_param("host")
        if host_header:
            ws_opts["headers"] = {"Host": host_header}
        if ws_opts:
            proxy["ws-opts"] = ws_opts

    if network == "grpc":
        service_name = get_param("serviceName") or get_param("service_name")
        if service_name:
            proxy["grpc-opts"] = {"grpc-service-name": service_name}

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
            proxy.get("name"),
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
        if name not in counts:
            counts[name] = 1
            continue
        counts[name] += 1
        proxy["name"] = f"{name}-{counts[name]}"


def build_output(proxies: List[Dict[str, object]]) -> Dict[str, object]:
    return {"proxies": proxies}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse VLESS links from open sources and export Clash YAML."
    )
    parser.add_argument(
        "--sources",
        type=Path,
        default=Path("sources.yaml"),
        help="Path to sources YAML file.",
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

    all_links: List[str] = []
    for url in sources:
        try:
            content = fetch_url(url)
        except Exception as exc:
            print(f"[warn] {url}: {exc}")
            continue
        all_links.extend(extract_links(content))

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
    print(f"Saved {len(proxies)} proxies to {args.output}")


if __name__ == "__main__":
    main()
