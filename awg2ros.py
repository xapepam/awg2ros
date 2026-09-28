#!/usr/bin/env python3
"""
awg2ros.py — генератор команд RouterOS для смены VPN-локации awg-proxy.
Автоматически ротирует старые файлы перед записью (name_1, name_2, ...).
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from ipaddress import ip_address

OBF_MAP = {
    "jc": "AWG_JC",
    "jmin": "AWG_JMIN",
    "jmax": "AWG_JMAX",
    "s1": "AWG_S1",
    "s2": "AWG_S2",
    "h1": "AWG_H1",
    "h2": "AWG_H2",
    "h3": "AWG_H3",
    "h4": "AWG_H4",
}


@dataclass
class Conf:
    private_key: str = ""
    address: str = ""
    mtu: int | None = None
    public_key: str = ""
    endpoint_host: str = ""
    endpoint_port: int | None = None
    keepalive: int | None = None
    obf: dict[str, str] = field(default_factory=dict)

    @property
    def endpoint(self) -> str:
        return f"{self.endpoint_host}:{self.endpoint_port}"

    @property
    def endpoint_is_ip(self) -> bool:
        if not self.endpoint_host:
            return False
        try:
            ip_address(self.endpoint_host)
            return True
        except ValueError:
            return False


def parse_conf(text: str) -> Conf:
    c = Conf()
    section = None

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue

        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue

        if "=" not in line:
            continue

        k, v = line.split("=", 1)
        k = k.strip().lower()
        v = v.strip(" \t\r\n\"'")
        if not v:
            continue

        if k in OBF_MAP:
            c.obf[k] = v
            continue

        if section == "interface":
            if k == "privatekey":
                c.private_key = v
            elif k == "address":
                c.address = v.split(",")[0].strip()
            elif k == "mtu":
                try:
                    c.mtu = int(v)
                except ValueError:
                    pass
        elif section == "peer":
            if k == "publickey":
                c.public_key = v
            elif k == "endpoint":
                host, _, port = v.rpartition(":")
                c.endpoint_host = host.strip("[]")
                try:
                    c.endpoint_port = int(port)
                except ValueError:
                    pass
            elif k == "persistentkeepalive":
                try:
                    c.keepalive = int(v)
                except ValueError:
                    pass

    return c


def generate(c: Conf, a: argparse.Namespace) -> list[str]:
    out = []
    p = out.append

    tag = a.tag
    iface = a.iface
    env = a.envlist
    cont = a.container

    p("# ===========================================")
    p(f"#  Смена локации awg-proxy -> {c.endpoint}")
    p("# ============================================================")
    p("")
    p("# --- 1. Резервная копия ---")
    p(f"/system/backup/save name={tag}-before-switch")
    p("")
    p("# --- 2. Остановка контейнера ---")
    p(f'/container/stop [find where comment~"{cont}"]')
    p("")
    p("# --- 3. WireGuard интерфейс и адрес ---")
    mtu_part = f" mtu={c.mtu}" if c.mtu else ""
    p(f'/interface/wireguard/set [find where name="{iface}"] private-key="{c.private_key}"{mtu_part}')
    if c.address:
        p(f'/ip/address/remove [find where interface="{iface}"]')
        p(f'/ip/address/add interface="{iface}" address={c.address}')
    p("")
    p("# --- 4. Настройки пира ---")
    ka_part = f" persistent-keepalive={c.keepalive}s" if c.keepalive else ""
    p(f'/interface/wireguard/peers/set [find where interface="{iface}"] public-key="{c.public_key}"{ka_part}')
    p("")
    p("# --- 5. Переменные контейнера (используется key=) ---")
    p("{")
    p(":local setenv do={")
    p(f'  :local id [/container/envs/find where list="{env}" and key=$1]')
    p("  :if ([:len $id] > 0) do={")
    p("    /container/envs/set $id value=$2")
    p("  } else={")
    p(f'    /container/envs/add list="{env}" key=$1 value=$2')
    p("  }")
    p("}")
    p(f':local pub [/interface/wireguard/get [find where name="{iface}"] public-key]')
    p('$setenv "AWG_CLIENT_PUB" $pub')
    p(f'$setenv "AWG_REMOTE" "{c.endpoint}"')
    p(f'$setenv "AWG_SERVER_PUB" "{c.public_key}"')
    for k, name in OBF_MAP.items():
        if k in c.obf:
            p(f'$setenv "{name}" "{c.obf[k]}"')
    p("}")
    p("")
    p("# --- 6. Маршрут к Endpoint через WAN (защита от петли) ---")
    p('/ip/route/remove [find where comment~"endpoint"]')
    if c.endpoint_is_ip:
        p("{")
        p(':local gw [/ip/route/get [find where dst-address=0.0.0.0/0 and active and routing-table="main"] gateway]')
        p(f'/ip/route/add dst-address={c.endpoint_host}/32 gateway=$gw distance=1 comment="{tag}-endpoint"')
        p("}")
    p("")
    p("# --- 7. Запуск контейнера и сброс соединений ---")
    p(f'/container/start [find where comment~"{cont}"]')
    p("/ip/dns/cache/flush")
    p("/ip/firewall/connection/remove [find]")
    p("")
    p("# --- 8. Проверка через 10 секунд ---")
    p(f'/interface/wireguard/peers/print detail where interface="{iface}"')

    return out


def rotate_file(filepath: str) -> str | None:
    """
    Если filepath существует, переименовывает его в имя с инкрементом (_1, _2...).
    Возвращает новое имя файла.
    """
    if not os.path.exists(filepath):
        return None

    base, ext = os.path.splitext(filepath)
    counter = 1
    while True:
        candidate = f"{base}_{counter}{ext}"
        if not os.path.exists(candidate):
            break
        counter += 1

    try:
        os.rename(filepath, candidate)
        return candidate
    except OSError as e:
        print(f"Предупреждение: не удалось переместить старый {filepath} в {candidate}: {e}", file=sys.stderr)
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="AmneziaWG .conf -> команды RouterOS")
    ap.add_argument("conf", help="путь к .conf файлу")
    ap.add_argument("--tag", default="awg-proxy-1")
    ap.add_argument("--iface", default="wg-awg-proxy-1")
    ap.add_argument("--container", default="awg-proxy-1")
    ap.add_argument("--envlist", default="awg-proxy-1-env")
    ap.add_argument("-o", "--output", default="switch.rsc")
    args = ap.parse_args()

    try:
        with open(args.conf, encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Ошибка: файл {args.conf} не найден", file=sys.stderr)
        return 1

    if not content.strip():
        print(f"Ошибка: файл {args.conf} пуст", file=sys.stderr)
        return 1

    cfg = parse_conf(content)

    if not cfg.private_key or not cfg.endpoint_host:
        print("Ошибка: в конфиге не найдены обязательные параметры (PrivateKey / Endpoint)", file=sys.stderr)
        return 1

    commands = "\n".join(generate(cfg, args)) + "\n"

    # Ротируем предыдущий файл, если он уже есть
    archived = rotate_file(args.output)
    if archived:
        print(f"Предыдущий файл сохранён как: {archived}")

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(commands)
    except OSError as e:
        print(f"Ошибка записи в файл {args.output}: {e}", file=sys.stderr)
        return 1

    print(f"Готово! Новый скрипт записан в: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
