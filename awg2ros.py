#!/usr/bin/env python3
"""
awg2ros.py — генератор команд RouterOS для смены VPN-локации awg-proxy.
Генерирует основной конфигурационный скрипт (.rsc) и скрипт диагностики (check-command.txt).
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


def generate_main(c: Conf, tag: str, iface: str, env: str, cont: str, make_backup: bool = True) -> list[str]:
    out = []
    p = out.append

    p("# ============================================================")
    p(f"#  Смена локации awg-proxy -> {c.endpoint}")
    p("# ============================================================")
    p("")
    if make_backup:
        p("# --- 1. Резервная копия ---")
        p(f"/system/backup/save name={tag}-before-switch")
        p("")
    else:
        p("# --- 1. Резервная копия (пропущено пользователем) ---")
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


def generate_check(tag: str, iface: str, env: str, cont: str) -> str:
    lines = [
        "{",
        ':put "=== 1. WG INTERFACE & PEER ==="',
        f'/interface/wireguard/print detail where name="{iface}"',
        f'/interface/wireguard/peers/print detail where interface="{iface}"',
        "",
        ':put "=== 2. CONTAINER STATUS ==="',
        f'/container/print detail where comment~"{cont}"',
        "",
        ':put "=== 3. KEY MATCH CHECK ==="',
        f':local ifPub [/interface/wireguard/get [find where name="{iface}"] public-key]',
        f':local envPub [/container/envs/get [find where list="{env}" and key="AWG_CLIENT_PUB"] value]',
        ':put ("Interface Pub: " . $ifPub)',
        ':put ("Container Pub: " . $envPub)',
        ':if ($ifPub = $envPub) do={ :put "KEYS: MATCH (OK)" } else={ :put "KEYS: MISMATCH (ОШИБКА!)" }',
        "",
        ':put "=== 4. ENDPOINT ROUTE ==="',
        '/ip/route/print where comment~"endpoint"',
        "",
        ':put "=== 5. ROUTES IN TABLE ==="',
        f'/ip/route/print where routing-table="WG" or routing-table="{tag}-fwd-table"',
        "}",
    ]
    return "\n".join(lines) + "\n"


def rotate_file(filepath: str) -> str | None:
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
        print(f"Предупреждение: не удалось переместить {filepath} в {candidate}: {e}", file=sys.stderr)
        return None


# ----------------------------------------------------------------------
# Современный GUI (Dark Palette / Flat UI)
# ----------------------------------------------------------------------

def run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox

    C_BG = "#181825"
    C_PANEL = "#1e1e2e"
    C_INPUT = "#11111b"
    C_BORDER = "#313244"
    C_TEXT = "#cdd6f4"
    C_MUTED = "#9399b2"
    C_ACCENT = "#89b4fa"
    C_ACCENT_HOV = "#b4befe"
    C_SUCCESS = "#a6e3a1"
    C_DANGER = "#f38ba8"
    C_BTN_SEC = "#313244"
    C_BTN_SEC_HOV = "#45475a"

    FONT_UI = ("Noto Sans", 10)
    FONT_UI_BOLD = ("Noto Sans", 10, "bold")
    FONT_TITLE = ("Noto Sans", 12, "bold")
    FONT_CODE = ("JetBrains Mono", 10)
    if sys.platform == "win32":
        FONT_UI = ("Segoe UI", 10)
        FONT_UI_BOLD = ("Segoe UI", 10, "bold")
        FONT_TITLE = ("Segoe UI", 12, "bold")
        FONT_CODE = ("Consolas", 10)

    root = tk.Tk()
    root.title("awg2ros — AmneziaWG to RouterOS Generator")
    root.geometry("1080x760")
    root.minsize(860, 600)
    root.configure(bg=C_BG)

    def create_btn(parent, text, cmd, primary=False, bg=None, fg=None, hov=None):
        btn_bg = bg or (C_ACCENT if primary else C_BTN_SEC)
        btn_fg = fg or ("#11111b" if primary else C_TEXT)
        btn_hov = hov or (C_ACCENT_HOV if primary else C_BTN_SEC_HOV)

        btn = tk.Button(
            parent,
            text=text,
            command=cmd,
            font=FONT_UI_BOLD if primary else FONT_UI,
            bg=btn_bg,
            fg=btn_fg,
            activebackground=btn_hov,
            activeforeground=btn_fg,
            bd=0,
            padx=12,
            pady=6,
            cursor="hand2",
            relief=tk.FLAT,
        )
        btn.bind("<Enter>", lambda e: btn.configure(bg=btn_hov))
        btn.bind("<Leave>", lambda e: btn.configure(bg=btn_bg))
        return btn

    def make_scroll_text(parent):
        frame = tk.Frame(parent, bg=C_BORDER, bd=1)
        txt = tk.Text(
            frame,
            bg=C_INPUT,
            fg=C_TEXT,
            insertbackground=C_TEXT,
            selectbackground="#45475a",
            selectforeground=C_TEXT,
            font=FONT_CODE,
            wrap=tk.NONE,
            bd=0,
            padx=10,
            pady=10,
            undo=True,
        )
        sb = tk.Scrollbar(frame, orient=tk.VERTICAL, command=txt.yview, bg=C_PANEL, troughcolor=C_INPUT, bd=0)
        txt.configure(yscrollcommand=sb.set)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        return frame, txt

    # --- Header ---
    hdr = tk.Frame(root, bg=C_PANEL, height=48, padx=16, pady=10)
    hdr.pack(fill=tk.X, side=tk.TOP)

    t_title = tk.Label(hdr, text="awg2ros", font=FONT_TITLE, fg=C_ACCENT, bg=C_PANEL)
    t_title.pack(side=tk.LEFT)
    t_sub = tk.Label(hdr, text="• Смена локации AmneziaWG + генератор проверки", font=FONT_UI, fg=C_MUTED, bg=C_PANEL)
    t_sub.pack(side=tk.LEFT, padx=10)

    # --- Top File Bar ---
    top_bar = tk.Frame(root, bg=C_BG, padx=16, pady=10)
    top_bar.pack(fill=tk.X)

    path_var = tk.StringVar()
    entry_f = tk.Frame(top_bar, bg=C_BORDER, bd=1)
    entry_f.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

    file_entry = tk.Entry(
        entry_f,
        textvariable=path_var,
        bg=C_INPUT,
        fg=C_TEXT,
        insertbackground=C_TEXT,
        font=FONT_UI,
        bd=0,
    )
    file_entry.pack(fill=tk.BOTH, ipady=6, padx=8)

    def browse_file():
        fn = filedialog.askopenfilename(
            title="Выберите .conf",
            filetypes=[("WireGuard Config", "*.conf"), ("Все файлы", "*.*")]
        )
        if fn:
            path_var.set(fn)
            try:
                with open(fn, encoding="utf-8") as f:
                    in_text.delete("1.0", tk.END)
                    in_text.insert(tk.END, f.read())
                do_generate()
            except Exception as e:
                set_status(f"Ошибка чтения: {e}", C_DANGER)
                messagebox.showerror("Ошибка", f"Не удалось прочитать файл:\n{e}")

    btn_browse = create_btn(top_bar, "Обзор файла...", browse_file)
    btn_browse.pack(side=tk.RIGHT)

    # --- Options Ribbon ---
    opt_card = tk.Frame(root, bg=C_PANEL, padx=14, pady=8, highlightbackground=C_BORDER, highlightthickness=1)
    opt_card.pack(fill=tk.X, padx=16, pady=(0, 10))

    tag_var = tk.StringVar(value="awg-proxy-1")
    iface_var = tk.StringVar(value="wg-awg-proxy-1")
    cont_var = tk.StringVar(value="awg-proxy-1")
    env_var = tk.StringVar(value="awg-proxy-1-env")
    out_var = tk.StringVar(value="switch.rsc")
    check_var = tk.StringVar(value="check-command.txt")
    backup_var = tk.BooleanVar(value=True)

    fields = [
        ("Tag:", tag_var, 11),
        ("Интерфейс:", iface_var, 13),
        ("Контейнер:", cont_var, 12),
        ("Envlist:", env_var, 13),
        ("Выходной .rsc:", out_var, 11),
        ("Файл проверки:", check_var, 14),
    ]

    for col, (label_t, v, w) in enumerate(fields):
        col_frame = tk.Frame(opt_card, bg=C_PANEL)
        col_frame.grid(row=0, column=col, padx=5, sticky="w")
        tk.Label(col_frame, text=label_t, font=FONT_UI, fg=C_MUTED, bg=C_PANEL).pack(anchor="w")

        e_wrap = tk.Frame(col_frame, bg=C_BORDER, bd=1)
        e_wrap.pack(anchor="w", pady=(2, 0))
        e = tk.Entry(e_wrap, textvariable=v, width=w, bg=C_INPUT, fg=C_TEXT, insertbackground=C_TEXT, font=FONT_UI, bd=0)
        e.pack(ipady=4, padx=6)

    cb_frame = tk.Frame(opt_card, bg=C_PANEL)
    cb_frame.grid(row=0, column=len(fields), padx=(8, 0), sticky="e")
    tk.Label(cb_frame, text="Опции:", font=FONT_UI, fg=C_MUTED, bg=C_PANEL).pack(anchor="w")

    cb_backup = tk.Checkbutton(
        cb_frame,
        text="Делать бэкап",
        variable=backup_var,
        font=FONT_UI,
        bg=C_PANEL,
        fg=C_TEXT,
        activebackground=C_PANEL,
        activeforeground=C_ACCENT,
        selectcolor=C_INPUT,
        highlightthickness=0,
        bd=0,
        cursor="hand2",
    )
    cb_backup.pack(anchor="w", pady=(4, 0))

    # --- Work Area ---
    work_area = tk.Frame(root, bg=C_BG, padx=16)
    work_area.pack(fill=tk.BOTH, expand=True)

    work_area.columnconfigure(0, weight=1, uniform="group1")
    work_area.columnconfigure(1, weight=1, uniform="group1")
    work_area.rowconfigure(1, weight=1)

    # Заголовок слева
    lbl_left = tk.Label(work_area, text="Конфигурация источника (.conf)", font=FONT_UI_BOLD, fg=C_TEXT, bg=C_BG)
    lbl_left.grid(row=0, column=0, sticky="w", pady=(0, 4))

    # Переключатель вкладок справа
    right_tab_bar = tk.Frame(work_area, bg=C_BG)
    right_tab_bar.grid(row=0, column=1, sticky="w", pady=(0, 4), padx=(4, 0))

    current_tab = "main"

    f_left, in_text = make_scroll_text(work_area)
    f_left.grid(row=1, column=0, sticky="nsew", padx=(0, 4))

    # Правые контейнеры (switch.rsc и check-command.txt)
    f_right_main, out_text_main = make_scroll_text(work_area)
    f_right_check, out_text_check = make_scroll_text(work_area)

    f_right_main.grid(row=1, column=1, sticky="nsew", padx=(4, 0))
    f_right_check.grid(row=1, column=1, sticky="nsew", padx=(4, 0))
    f_right_main.tkraise()

    def show_tab(tab_name):
        nonlocal current_tab
        current_tab = tab_name
        if tab_name == "main":
            f_right_main.tkraise()
            btn_tab_main.configure(bg=C_ACCENT, fg="#11111b")
            btn_tab_check.configure(bg=C_BTN_SEC, fg=C_TEXT)
        else:
            f_right_check.tkraise()
            btn_tab_check.configure(bg=C_ACCENT, fg="#11111b")
            btn_tab_main.configure(bg=C_BTN_SEC, fg=C_TEXT)

    btn_tab_main = tk.Button(
        right_tab_bar, text=" 📄 switch.rsc ", font=FONT_UI_BOLD,
        bg=C_ACCENT, fg="#11111b", bd=0, padx=8, pady=2, cursor="hand2", relief=tk.FLAT,
        command=lambda: show_tab("main")
    )
    btn_tab_main.pack(side=tk.LEFT, padx=(0, 4))

    btn_tab_check = tk.Button(
        right_tab_bar, text=" 🩺 check-command.txt ", font=FONT_UI,
        bg=C_BTN_SEC, fg=C_TEXT, bd=0, padx=8, pady=2, cursor="hand2", relief=tk.FLAT,
        command=lambda: show_tab("check")
    )
    btn_tab_check.pack(side=tk.LEFT)

    # --- Bottom Actions Bar ---
    bot_bar = tk.Frame(root, bg=C_PANEL, padx=16, pady=10)
    bot_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=(10, 0))

    status_dot = tk.Label(bot_bar, text="●", font=FONT_UI_BOLD, fg=C_MUTED, bg=C_PANEL)
    status_dot.pack(side=tk.LEFT)

    status_lbl = tk.Label(bot_bar, text="Готов к работе", font=FONT_UI, fg=C_MUTED, bg=C_PANEL)
    status_lbl.pack(side=tk.LEFT, padx=6)

    def set_status(msg, color=C_MUTED):
        status_lbl.configure(text=msg, fg=color)
        status_dot.configure(fg=color)

    def do_generate():
        raw = in_text.get("1.0", tk.END).strip()
        if not raw:
            set_status("Ошибка: вставьте текст конфигурации или выберите файл", C_DANGER)
            return None, None

        cfg = parse_conf(raw)
        if not cfg.private_key or not cfg.endpoint_host:
            set_status("Ошибка: в конфиге нет PrivateKey или Endpoint", C_DANGER)
            return None, None

        tag = tag_var.get().strip()
        iface = iface_var.get().strip()
        env = env_var.get().strip()
        cont = cont_var.get().strip()

        commands_main = "\n".join(generate_main(
            cfg, tag=tag, iface=iface, env=env, cont=cont, make_backup=backup_var.get(),
        )) + "\n"

        commands_check = generate_check(tag=tag, iface=iface, env=env, cont=cont)

        out_text_main.delete("1.0", tk.END)
        out_text_main.insert(tk.END, commands_main)

        out_text_check.delete("1.0", tk.END)
        out_text_check.insert(tk.END, commands_check)

        set_status(f"Сгенерировано: switch.rsc и check-command.txt ({cfg.endpoint})", C_SUCCESS)
        return commands_main, commands_check

    def do_copy_main():
        res = out_text_main.get("1.0", tk.END).strip()
        if not res:
            res, _ = do_generate()
        if res:
            root.clipboard_clear()
            root.clipboard_append(out_text_main.get("1.0", tk.END))
            set_status("Команды switch.rsc скопированы в буфер!", C_SUCCESS)

    def do_copy_check():
        res = out_text_check.get("1.0", tk.END).strip()
        if not res:
            _, res = do_generate()
        if res:
            root.clipboard_clear()
            root.clipboard_append(out_text_check.get("1.0", tk.END))
            set_status("Команда проверки скопирована в буфер!", C_SUCCESS)

    def do_save():
        main_text = out_text_main.get("1.0", tk.END).strip()
        check_text = out_text_check.get("1.0", tk.END).strip()
        if not main_text or not check_text:
            main_text, check_text = do_generate()
        if not main_text:
            return

        target_main = out_var.get().strip() or "switch.rsc"
        target_check = check_var.get().strip() or "check-command.txt"

        arch_main = rotate_file(target_main)
        arch_check = rotate_file(target_check)

        try:
            with open(target_main, "w", encoding="utf-8") as f:
                f.write(out_text_main.get("1.0", tk.END))
            with open(target_check, "w", encoding="utf-8") as f:
                f.write(out_text_check.get("1.0", tk.END))

            msg = f"Сохранено: {target_main} и {target_check}"
            if arch_main or arch_check:
                msg += " (предыдущие ротированы)"
            set_status(msg, C_SUCCESS)
        except Exception as e:
            set_status(f"Ошибка сохранения: {e}", C_DANGER)
            messagebox.showerror("Ошибка", f"Не удалось сохранить файлы:\n{e}")

    def do_clear():
        in_text.delete("1.0", tk.END)
        out_text_main.delete("1.0", tk.END)
        out_text_check.delete("1.0", tk.END)
        path_var.set("")
        set_status("Очищено", C_MUTED)

    # Кнопки справа в футере
    btn_save = create_btn(bot_bar, "Сохранить файлы", do_save)
    btn_save.pack(side=tk.RIGHT, padx=(6, 0))

    btn_copy_check = create_btn(bot_bar, "Скопировать проверку", do_copy_check)
    btn_copy_check.pack(side=tk.RIGHT, padx=(6, 0))

    btn_copy_main = create_btn(bot_bar, "Скопировать .rsc", do_copy_main)
    btn_copy_main.pack(side=tk.RIGHT, padx=(6, 0))

    btn_gen = create_btn(bot_bar, "Сгенерировать", do_generate, primary=True)
    btn_gen.pack(side=tk.RIGHT, padx=(6, 0))

    btn_clear = create_btn(bot_bar, "Очистить", do_clear)
    btn_clear.pack(side=tk.RIGHT, padx=(6, 0))

    root.bind("<Control-Return>", lambda e: do_generate())

    root.mainloop()


# ----------------------------------------------------------------------
# Консольный режим (CLI)
# ----------------------------------------------------------------------

def run_cli():
    ap = argparse.ArgumentParser(description="AmneziaWG .conf -> команды RouterOS")
    ap.add_argument("conf", nargs="?", help="путь к .conf файлу")
    ap.add_argument("--gui", action="store_true", help="принудительно запустить GUI")
    ap.add_argument("--tag", default="awg-proxy-1")
    ap.add_argument("--iface", default="wg-awg-proxy-1")
    ap.add_argument("--container", default="awg-proxy-1")
    ap.add_argument("--envlist", default="awg-proxy-1-env")
    ap.add_argument("-o", "--output", default="switch.rsc")
    ap.add_argument("--check-output", default="check-command.txt",
                    help="имя файла с командой проверки (по умолчанию: check-command.txt)")
    ap.add_argument("--no-backup", dest="make_backup", action="store_false", default=True,
                    help="не добавлять команду создания бэкапа перед сменой")
    args = ap.parse_args()

    if args.gui or not args.conf:
        run_gui()
        return 0

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

    commands_main = "\n".join(generate_main(
        cfg,
        tag=args.tag,
        iface=args.iface,
        env=args.envlist,
        cont=args.container,
        make_backup=args.make_backup,
    )) + "\n"

    commands_check = generate_check(
        tag=args.tag,
        iface=args.iface,
        env=args.envlist,
        cont=args.container,
    )

    # Ротация обоих файлов
    arch_main = rotate_file(args.output)
    arch_check = rotate_file(args.check_output)

    if arch_main:
        print(f"Предыдущий .rsc сохранён как: {arch_main}")
    if arch_check:
        print(f"Предыдущая проверка сохранена как: {arch_check}")

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(commands_main)
        with open(args.check_output, "w", encoding="utf-8") as f:
            f.write(commands_check)
    except OSError as e:
        print(f"Ошибка записи файлов: {e}", file=sys.stderr)
        return 1

    print(f"Готово! Записано:\n  • {args.output}\n  • {args.check_output}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        run_gui()
    else:
        raise SystemExit(run_cli())
