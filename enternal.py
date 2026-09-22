# language: Python 3.10+, file: there.py
# установка: pip install requests phonenumbers dnspython python-whois pytz
# запуск: python there.py

import os, sys, re, time, json, socket, ssl, hashlib, base64, random
from datetime import datetime
from pathlib import Path

# ── проверка зависимостей ──
missing = []
try: import requests
except ImportError: missing.append("requests")
try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone, number_type, PhoneNumberType
except ImportError: missing.append("phonenumbers")
try: import dns.resolver
except ImportError: missing.append("dnspython")
try: import whois as python_whois
except ImportError: missing.append("python-whois")
try: import pytz
except ImportError: pass

if missing:
    print("НЕ УСТАНОВЛЕНО:", ", ".join(missing))
    print(f"pip install {' '.join(missing)}")
    input("Enter..."); sys.exit(1)

# ── пути ──
RESULTS_DIR = Path("results"); RESULTS_DIR.mkdir(exist_ok=True)
HISTORY_FILE = "there_history.json"
CONFIG_FILE = "there_config.json"
WEBHOOK_FILE = "there_webhook.json"
VK_TOKEN_FILE = "there_vk_token.txt"
VT_TOKEN_FILE = "there_vt_token.txt"
MONITOR_FILE = "there_monitor.json"
LOG_FILE = "there_logs.json"

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0"
TIMEOUT = 10

DEFAULT_CONFIG = {
    "timeout": 10,
    "save_results": True,
    "use_proxy": False,
    "proxy_url": "socks5h://127.0.0.1:9050",
    "paranoia": False,
    "log_all": True,
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return {**DEFAULT_CONFIG, **json.load(f)}
        except: pass
    return DEFAULT_CONFIG.copy()

def save_config():
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(CONFIG, f, indent=2, ensure_ascii=False)
    except: pass

CONFIG = load_config()

if os.name == "nt": os.system("")

class C:
    RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    BLUE="\033[94m"; MAGENTA="\033[95m"; CYAN="\033[96m"; WHITE="\033[97m"

BANNER = r"""
▄▄▄█████▓ ██░ ██ ▓█████  ██▀███  ▓█████     ▄▄▄██▀▀▀█
▓  ██▒ ▓▒▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒▓█   ▀       ▒██
▒ ▓██░ ▒░▒██▀▀██░▒███   ▓██ ░▄█ ▒▒███         ░██
░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄  ▒▓█  ▄    ▓██▄▄██▄
  ▒██▒ ░ ░▓█▒░██▓░▒████▒░██▓ ▒██▒░▒████▒     ▒▓█   ▓
  ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░░░ ▒░ ░     ▒▒   ▓▒█
    ░     ▒ ░▒░ ░ ░ ░  ░  ░▒ ░ ▒░ ░ ░  ░      ░   ▒▒
  ░       ░  ░░ ░   ░     ░░   ░    ░         ░   ▒
          ░  ░  ░   ░  ░   ░        ░  ░          ░
"""

def clear(): os.system("cls" if os.name == "nt" else "clear")
def header():
    clear()
    print(f"{C.CYAN}{BANNER}{C.RESET}")
    print(f"{C.BLUE}═══ OSINT TOOL v4.0 · by DEK0 ═══".center(70) + f"{C.RESET}\n")
def pause(): input(f"\n{C.DIM}Enter...{C.RESET}")
def prompt(t): return input(f"{C.GREEN}[?]{C.RESET} {t}: ").strip()
def ok(t): print(f"{C.GREEN}[+]{C.RESET} {t}")
def info(t): print(f"{C.CYAN}[i]{C.RESET} {t}")
def warn(t): print(f"{C.YELLOW}[!]{C.RESET} {t}")
def err(t): print(f"{C.RED}[-]{C.RESET} {t}")
def line(l, v): print(f"  {C.DIM}{l:22}{C.RESET} {C.WHITE}{v}{C.RESET}")
def section(t): print(f"\n  {C.MAGENTA}─── {t} ───{C.RESET}")
def result_header(t):
    print(f"\n{C.CYAN}{'═'*60}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  {t}{C.RESET}")
    print(f"{C.CYAN}{'═'*60}{C.RESET}\n")

def is_paranoia():
    if CONFIG.get("paranoia"):
        err("Заблокировано режимом паранойи")
        pause()
        return True
    return False

def get_proxies():
    if not CONFIG.get("use_proxy"):
        return None
    p = CONFIG.get("proxy_url", "socks5h://127.0.0.1:9050")
    return {"http": p, "https": p}

def rget(url, **kw):
    px = get_proxies()
    if px: kw["proxies"] = px
    kw.setdefault("timeout", TIMEOUT)
    kw.setdefault("headers", {"User-Agent": UA})
    log_request(url, "GET")
    return requests.get(url, **kw)

def rhead(url, **kw):
    px = get_proxies()
    if px: kw["proxies"] = px
    kw.setdefault("timeout", TIMEOUT)
    kw.setdefault("headers", {"User-Agent": UA})
    kw.setdefault("allow_redirects", True)
    log_request(url, "HEAD")
    return requests.head(url, **kw)

def rpost(url, **kw):
    px = get_proxies()
    if px: kw["proxies"] = px
    kw.setdefault("timeout", TIMEOUT)
    kw.setdefault("headers", {"User-Agent": UA})
    log_request(url, "POST")
    return requests.post(url, **kw)

# ═══ ЛОГИ ═══
def log_request(url, method="GET"):
    if not CONFIG.get("log_all"): return
    try:
        logs = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
        logs.insert(0, {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "method": method,
            "url": url[:200],
            "proxy": CONFIG.get("proxy_url") if CONFIG.get("use_proxy") else None,
        })
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(logs[:1000], f, indent=2, ensure_ascii=False)
    except: pass

def show_logs():
    header(); result_header("ЛОГИ ЗАПРОСОВ")
    if not os.path.exists(LOG_FILE):
        info("Логов нет"); pause(); return
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = json.load(f)
    except:
        err("Ошибка чтения"); pause(); return
    if not logs:
        info("Пусто"); pause(); return
    info(f"Всего: {len(logs)}")
    print()
    for i, e in enumerate(logs[:50], 1):
        proxy_mark = f" {C.DIM}[tor]{C.RESET}" if e.get("proxy") else ""
        print(f"  {C.CYAN}[{i:>3}]{C.RESET} {C.DIM}{e['timestamp']}{C.RESET}{proxy_mark}")
        print(f"        {C.WHITE}{e['method']}{C.RESET} {e['url']}")
    print()
    ch = input(f"{C.YELLOW}Очистить логи? [y/N]: {C.RESET}").strip().lower()
    if ch in ("y","yes","д","да"):
        with open(LOG_FILE, "w") as f: json.dump([], f)
        ok("Очищено"); time.sleep(1)

# ═══ ИСТОРИЯ ═══
def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f: return json.load(f)
        except: return []
    return []

def save_history(h):
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(h[:200], f, indent=2, ensure_ascii=False)
    except: pass

def log_history(cmd, target, summary=""):
    h = load_history()
    h.insert(0, {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 "command": cmd, "target": target, "summary": summary[:200]})
    save_history(h)

def save_result(text, prefix="result"):
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe = re.sub(r'[^\w\-]', '_', prefix)[:50]
    fp = RESULTS_DIR / f"{ts}_{safe}.txt"
    try:
        with open(fp, "w", encoding="utf-8") as f: f.write(text)
        ok(f"Сохранено: {fp}")
    except Exception as e: err(f"Ошибка: {e}")

def ask_save(text, prefix="result"):
    if not CONFIG.get("save_results"): return
    ch = input(f"\n{C.DIM}Сохранить? [y/N]: {C.RESET}").strip().lower()
    if ch in ("y","yes","д","да"): save_result(text, prefix)

def parse_num(s):
    clean = re.sub(r'[^\d+]', '', s)
    if not clean.startswith("+") and not clean.startswith("00"):
        if clean.startswith(("380","7","1","44","48")): clean = "+" + clean
    try:
        p = phonenumbers.parse(clean, None)
        return p, str(p.country_code) + str(p.national_number), None
    except Exception as e: return None, None, str(e)

# ═══ МОНИТОРИНГ ═══
def load_monitors():
    if os.path.exists(MONITOR_FILE):
        try:
            with open(MONITOR_FILE, "r", encoding="utf-8") as f: return json.load(f)
        except: return []
    return []

def save_monitors(d):
    try:
        with open(MONITOR_FILE, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2, ensure_ascii=False)
    except: pass

def check_monitor_phone(m):
    """Проверяет состояние по номеру."""
    p, digits, e = parse_num(m["target"])
    if e: return "ошибка парсинга"
    state = {}
    try:
        r = rhead(f"https://wa.me/{digits}", timeout=8)
        state["whatsapp"] = r.status_code == 200
    except: state["whatsapp"] = None
    try:
        r = rget(f"https://t.me/+{digits}", timeout=8)
        state["telegram"] = r.status_code == 200 and "tgme" in r.text
    except: state["telegram"] = None
    return json.dumps(state, ensure_ascii=False)

def do_monitor():
    while True:
        header(); result_header("МОНИТОРИНГ")
        monitors = load_monitors()
        if not monitors:
            info("Пусто")
        else:
            for i, m in enumerate(monitors, 1):
                print(f"  {C.CYAN}[{i}]{C.RESET} {m.get('type')}: {m['target']}")
                print(f"      {C.DIM}проверка: {m.get('last_check','—')}{C.RESET}")
                if m.get("last_state"):
                    print(f"      {C.DIM}состояние: {m['last_state'][:80]}{C.RESET}")
                print()
        print(f"  {C.GREEN}[1]{C.RESET} Добавить цель")
        print(f"  {C.GREEN}[2]{C.RESET} Проверить все")
        print(f"  {C.GREEN}[3]{C.RESET} Удалить")
        print(f"  {C.DIM}[0]{C.RESET} Назад")
        print()
        ch = prompt("Выбор")
        if ch == "0": return
        elif ch == "1":
            t = prompt("Тип (phone/telegram/domain/ip)")
            v = prompt("Цель")
            if t and v:
                monitors.append({"type": t, "target": v,
                    "added": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "last_check": None, "last_state": None})
                save_monitors(monitors)
                ok("Добавлено"); time.sleep(1)
        elif ch == "2":
            if not monitors: warn("Пусто"); time.sleep(1); continue
            for m in monitors:
                info(f"Проверка {m['target']}...")
                try:
                    if m["type"] == "phone":
                        state = check_monitor_phone(m)
                    elif m["type"] == "telegram":
                        nick = m["target"].lstrip("@")
                        r = rget(f"https://t.me/{nick}", timeout=8)
                        mm = re.search(r'tgme_page_title[^>]*>([^<]+)<', r.text)
                        state = mm.group(1).strip() if mm else "—"
                    elif m["type"] == "domain":
                        try:
                            w = python_whois.whois(m["target"])
                            state = str(w.registrar or "—")
                        except: state = "ошибка"
                    elif m["type"] == "ip":
                        r = rget(f"http://ip-api.com/json/{m['target']}?fields=isp,country")
                        d = r.json()
                        state = f"{d.get('isp','—')} | {d.get('country','—')}"
                    else: state = "?"
                    m["last_check"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if m.get("last_state") and m["last_state"] != state:
                        warn(f"ИЗМЕНЕНИЕ! {m['target']}")
                        print(f"    было:  {m['last_state'][:100]}")
                        print(f"    стало: {state[:100]}")
                    else:
                        ok(f"{m['target']}: {state[:80]}")
                    m["last_state"] = state
                except Exception as e:
                    err(f"{m['target']}: {e}")
                print()
            save_monitors(monitors)
            pause()
        elif ch == "3":
            if not monitors: warn("Пусто"); time.sleep(1); continue
            try:
                idx = int(prompt("Номер")) - 1
                if 0 <= idx < len(monitors):
                    monitors.pop(idx); save_monitors(monitors)
                    ok("Удалено"); time.sleep(1)
            except: err("Число"); time.sleep(1)

# ═══ НОВЫЕ ФУНКЦИИ: TELEGRAM/VIBER/SIGNAL ПО НОМЕРУ ═══

def do_tg_by_phone():
    header(); result_header("TELEGRAM ПО НОМЕРУ")
    if is_paranoia(): return
    n = prompt("Номер")
    if not n: err("Не введено"); pause(); return
    p, digits, e = parse_num(n)
    if e: err(e); pause(); return
    output = []
    def out(l, v): line(l, v); output.append(f"{l}: {v}")
    out("Номер", n)
    out("Цифры", digits)
    info("Проверяю через публичные ссылки...")
    print()
    try:
        r = rget(f"https://t.me/+{digits}", timeout=10)
        if r.status_code == 200 and "tgme_page" in r.text:
            ok("Аккаунт зарегистрирован")
            out("Telegram", "✅ зарегистрирован")
            m = re.search(r'tgme_page_title[^>]*>([^<]+)<', r.text)
            if m: out("Имя", m.group(1).strip())
            m = re.search(r'tgme_page_extra">([^<]+)<', r.text)
            if m: out("Инфо", m.group(1).strip())
        else:
            warn("Аккаунт не найден или скрыт")
            out("Telegram", "❌ не найден")
    except Exception as e: err(f"Ошибка: {e}")
    out("Ссылка", f"https://t.me/+{digits}")
    log_history("tg_by_phone", n)
    ask_save("\n".join(output), f"tg_phone_{digits}")


def do_viber_check():
    header(); result_header("VIBER CHECK")
    if is_paranoia(): return
    n = prompt("Номер")
    if not n: err("Не введено"); pause(); return
    p, digits, e = parse_num(n)
    if e: err(e); pause(); return
    output = []
    def out(l, v): line(l, v); output.append(f"{l}: {v}")
    out("Номер", n)
    out("Цифры", digits)
    info("Проверяю Viber...")
    print()
    try:
        # viber.com/chat?number=+номер — публичный endpoint
        url = f"https://www.viber.com/en/chat?number=%2B{digits}"
        r = rget(url, timeout=10, allow_redirects=True)
        if "viber.com" in r.url or r.status_code == 200:
            out("Viber", "✅ возможно есть (проверь в приложении)")
        else:
            out("Viber", "❌ не найден")
    except Exception as e: err(f"Ошибка: {e}")
    out("Проверка вручную", f"viber://chat?number=%2B{digits}")
    log_history("viber", n)
    ask_save("\n".join(output), f"viber_{digits}")


def do_signal_check():
    header(); result_header("SIGNAL CHECK")
    if is_paranoia(): return
    n = prompt("Номер")
    if not n: err("Не введено"); pause(); return
    p, digits, e = parse_num(n)
    if e: err(e); pause(); return
    output = []
    def out(l, v): line(l, v); output.append(f"{l}: {v}")
    out("Номер", n)
    out("Цифры", digits)
    info("Проверяю Signal...")
    print()
    try:
        # signal.me профиль
        url = f"https://signal.me/#p/+{digits}"
        r = rget("https://signal.me/", timeout=10)
        out("Signal", "проверь вручную")
        out("Ссылка", url)
        info("Автоматическая проверка Signal недоступна — только через приложение")
    except Exception as e: err(f"Ошибка: {e}")
    log_history("signal", n)
    ask_save("\n".join(output), f"signal_{digits}")


def do_twitter_search():
    header(); result_header("TWITTER ПО НОМЕРУ")
    if is_paranoia(): return
    n = prompt("Номер или ник")
    if not n: err("Не введено"); pause(); return
    output = []
    def out(l, v): line(l, v); output.append(f"{l}: {v}")
    out("Запрос", n)
    info("Twitter API закрыт с 2023 — только Google Dorks и ссылки на поиск")
    print()
    clean = re.sub(r'[^\d+]', '', n)
    section("GOOGLE DORKS")
    out("Точный", f'https://www.google.com/search?q=site:twitter.com+"{n}"')
    out("X.com", f'https://www.google.com/search?q=site:x.com+"{n}"')
    out("Общий", f'https://www.google.com/search?q="{n}"+twitter')
    section("ПРЯМЫЕ ССЫЛКИ")
    out("Twitter поиск", f"https://twitter.com/search?q={n}")
    out("X поиск", f"https://x.com/search?q={n}")
    if clean:
        out("Twitter по цифрам", f"https://twitter.com/search?q={clean}")
    section("ЧЕРЕЗ ПЛАТНЫЕ СЕРВИСЫ")
    out("TweetAttacks", "https://tweetattacks.com/")
    out("PhantomBuster", "https://phantombuster.com/")
    log_history("twitter", n)
    ask_save("\n".join(output), f"twitter_{n}")


# ═══ VIRUSTOTAL ═══
def load_vt_token():
    if os.path.exists(VT_TOKEN_FILE):
        try:
            with open(VT_TOKEN_FILE) as f: return f.read().strip()
        except: return ""
    return ""

def do_virustotal():
    header(); result_header("VIRUSTOTAL")
    if is_paranoia(): return
    token = load_vt_token()
    if not token:
        warn("Нет API-ключа")
        info("Получи бесплатно: virustotal.com → профиль → API Key")
        t = prompt("Вставить сейчас? (y/n)")
        if t.lower() in ("y","yes","д","да"):
            tok = prompt("Токен")
            if tok:
                with open(VT_TOKEN_FILE, "w") as f: f.write(tok)
                ok("Сохранён"); time.sleep(1)
        return

    print(f"  {C.GREEN}[1]{C.RESET} Проверить домен")
    print(f"  {C.GREEN}[2]{C.RESET} Проверить IP")
    print(f"  {C.GREEN}[3]{C.RESET} Проверить хеш файла")
    print(f"  {C.GREEN}[4]{C.RESET} Проверить URL")
    print()
    kind = prompt("Выбор")

    target = prompt("Что проверить")
    if not target: pause(); return

    output = []
    def out(l, v): line(l, v); output.append(f"{l}: {v}")
    out("Запрос", target)

    headers = {"x-apikey": token, "User-Agent": UA}

    try:
        if kind == "1":
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
        elif kind == "2":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        elif kind == "3":
            url = f"https://www.virustotal.com/api/v3/files/{target}"
        elif kind == "4":
            import base64 as b64
            url_id = b64.urlsafe_b64encode(target.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else: return

        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 404:
            warn("Не найден в базе VT"); pause(); return
        if r.status_code == 401:
            err("Неверный API-ключ"); pause(); return
        if r.status_code != 200:
            err(f"HTTP {r.status_code}"); pause(); return

        d = r.json().get("data", {}).get("attributes", {})
        stats = d.get("last_analysis_stats", {})

        out("Вредоносных", stats.get("malicious", 0))
        out("Подозрительных", stats.get("suspicious", 0))
        out("Безопасных", stats.get("harmless", 0))
        out("Не проверено", stats.get("undetected", 0))

        if d.get("reputation") is not None:
            out("Репутация", d.get("reputation"))

        # детали
        if "categories" in d:
            cats = d["categories"]
            if cats: out("Категории", ", ".join(list(cats.values())[:5]))

        # движки, которые нашли
        engines = d.get("last_analysis_results", {})
        bad = [f"{k} ({v.get('result')})" for k, v in engines.items()
               if v.get("category") in ("malicious", "suspicious")]
        if bad:
            print(f"\n  {C.RED}Детекты:{C.RESET}")
            for b in bad[:15]:
                print(f"    ⚠ {b}")
                output.append(f"Детект: {b}")

        total = sum(stats.values())
        if total:
            ratio = f"{stats.get('malicious',0)}/{total}"
            color = C.GREEN if stats.get("malicious", 0) == 0 else C.RED
            print(f"\n  {color}Вердикт: {ratio}{C.RESET}")
            output.append(f"Вердикт: {ratio}")

    except Exception as e:
        err(f"Ошибка: {e}")

    log_history("virustotal", target)
    ask_save("\n".join(output), f"vt_{target.replace('/','_')[:30]}")


# ═══ ОСТАЛЬНЫЕ ФУНКЦИИ (сокращённо, работают как в v3.1) ═══

def do_phone_small():
    header(); result_header("НОМЕР · МАЛЕНЬКИЙ")
    if is_paranoia(): return
    n = prompt("Номер")
    if not n: pause(); return
    p, digits, e = parse_num(n)
    if e: err(e); pause(); return
    output = []
    def out(l, v): line(l, v); output.append(f"{l}: {v}")
    section("ОСНОВНОЕ")
    out("Страна", geocoder.description_for_number(p, "ru") or "—")
    out("Оператор", carrier.name_for_number(p, "ru") or "—")
    out("Номер", phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
    out("ISO", phonenumbers.region_code_for_number(p) or "—")
    section("ПРОВЕРКА")
    try:
        r = rhead(f"https://wa.me/{digits}", timeout=8)
        out("WhatsApp", "✅ есть" if r.status_code == 200 else "❌ нет")
    except: out("WhatsApp", "⚠")
    try:
        r = rget(f"https://t.me/+{digits}", timeout=8)
        out("Telegram", "✅ есть" if r.status_code == 200 and "tgme" in r.text else "❌ нет")
    except: out("Telegram", "⚠")
    log_history("phone_small", n)
    ask_save("\n".join(output), f"phone_small_{digits}")

def do_phone_big():
    header(); result_header("НОМЕР · БОЛЬШОЙ ДОКС")
    if is_paranoia(): return
    n = prompt("Номер")
    if not n: pause(); return
    p, digits, e = parse_num(n)
    if e: err(e); pause(); return
    output = [f"═══ БОЛЬШОЙ ДОКС ═══", f"Номер: {n}", f"Цифры: {digits}", ""]
    def out(l, v): line(l, v); output.append(f"{l}: {v}")
    c_ru = geocoder.description_for_number(p, "ru") or "—"
    c_en = geocoder.description_for_number(p, "en") or "—"
    op_ru = carrier.name_for_number(p, "ru") or "—"
    iso = phonenumbers.region_code_for_number(p) or "—"
    section("1. БАЗА")
    out("Страна (RU)", c_ru); out("Страна (EN)", c_en)
    out("Оператор", op_ru); out("ISO", iso)
    out("Код", f"+{p.country_code}"); out("Номер", str(p.national_number))
    section("2. ТИП")
    tm = {PhoneNumberType.MOBILE:"мобильный",PhoneNumberType.FIXED_LINE:"стационарный",
          PhoneNumberType.VOIP:"VoIP",PhoneNumberType.TOLL_FREE:"бесплатный",
          PhoneNumberType.PREMIUM_RATE:"премиум",PhoneNumberType.UNKNOWN:"?"}
    out("Тип", tm.get(number_type(p), "?"))
    section("3. ФОРМАТЫ")
    out("E.164", phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164))
    out("INT", phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
    out("NAT", phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.NATIONAL))
    section("4. ЧАСОВЫЕ ПОЯСА")
    tzs = timezone.time_zones_for_number(p)
    for tz in tzs:
        if tz != "Etc/Unknown": out("TZ", tz)
    section("5. ГЕОКОДИНГ")
    for lang in ["ru","en","de","es","fr","it","uk","pl"]:
        d = geocoder.description_for_number(p, lang)
        if d: out(f"({lang})", d)
    section("6. МЕССЕНДЖЕРЫ")
    out("WhatsApp", f"https://wa.me/{digits}")
    out("Telegram", f"https://t.me/+{digits}")
    out("Viber", f"viber://chat?number=%2B{digits}")
    out("Signal", f"https://signal.me/#p/+{digits}")
    section("7-8. ПРОВЕРКА")
    try:
        r = rhead(f"https://wa.me/{digits}", timeout=8)
        out("WhatsApp", "✅ есть" if r.status_code == 200 else "❌ нет")
    except: pass
    try:
        r = rget(f"https://t.me/+{digits}", timeout=8)
        out("Telegram", "✅ есть" if r.status_code == 200 and "tgme" in r.text else "❌ нет")
    except: pass
    section("9. АГРЕГАТОРЫ")
    i = iso.lower()
    for name, url in [
        ("Truecaller", f"https://www.truecaller.com/search/{i}/{digits}"),
        ("GetContact", f"https://getcontact.com/lookup/{digits}"),
        ("Sync.me", f"https://sync.me/search/?number={digits}"),
        ("EyeCon", f"https://eyecon-app.com/lookup?number={digits}"),
        ("Numlookup", f"https://www.numlookup.com/?phone={digits}"),
        ("SpyDialer", f"https://www.spydialer.com/default.aspx?phone={digits}"),
        ("Whitepages", f"https://www.whitepages.com/phone/{digits}"),
        ("FastPeople", f"https://www.fastpeoplesearch.com/{digits}"),
    ]: out(name, url)
    section("10. GOOGLE DORKS")
    for name, q in [
        ("точный", f'"{digits}"'), ("tg", f'"{digits}"+telegram'),
        ("vk", f'"{digits}"+site:vk.com'), ("ok", f'"{digits}"+site:ok.ru'),
        ("avito", f'"{digits}"+site:avito.ru'), ("olx", f'"{digits}"+site:olx.ua'),
    ]: out(name, f'https://www.google.com/search?q={q}')
    section("11. YANDEX/BING")
    out("Yandex", f'https://yandex.ru/search/?text="{digits}"')
    out("Bing", f'https://www.bing.com/search?q="{digits}"')
    section("12. СОЦСЕТИ")
    out("VK", f"https://vk.com/search?c[section]=people&c[q]={digits}")
    out("OK", f"https://ok.ru/search?st.query={digits}")
    out("TikTok", f"https://www.tiktok.com/search?q={digits}")
    section("13. УТЕЧКИ")
    for name, url in [
        ("LeakCheck", f"https://leakcheck.io/search?query={digits}"),
        ("Dehashed", f"https://dehashed.com/search?query={digits}"),
        ("IntelX", f"https://intelx.io/?s={digits}"),
    ]: out(name, url)
    section("14. ИТОГ")
    out("Ссылок", str(len([l for l in output if "http" in l])))
    log_history("phone_big", n)
    ask_save("\n".join(output), f"phone_big_{digits}")

def do_username():
    header(); result_header("НИК")
    if is_paranoia(): return
    nick = prompt("Ник")
    if not nick: pause(); return
    sites = {
        "GitHub": "https://github.com/{}", "Telegram": "https://t.me/{}",
        "Reddit": "https://reddit.com/user/{}", "Twitter/X": "https://x.com/{}",
        "Instagram": "https://instagram.com/{}", "TikTok": "https://tiktok.com/@{}",
        "YouTube": "https://youtube.com/@{}", "Steam": "https://steamcommunity.com/id/{}",
        "Twitch": "https://twitch.tv/{}", "VK": "https://vk.com/{}",
        "Pinterest": "https://pinterest.com/{}", "SoundCloud": "https://soundcloud.com/{}",
        "Spotify": "https://open.spotify.com/user/{}", "Behance": "https://behance.net/{}",
        "Medium": "https://medium.com/@{}", "Flickr": "https://flickr.com/people/{}",
        "Dribbble": "https://dribbble.com/{}", "Patreon": "https://patreon.com/{}",
        "Facebook": "https://facebook.com/{}", "LinkedIn": "https://linkedin.com/in/{}",
        "Keybase": "https://keybase.io/{}",
    }
    output = []; info(f"Проверяю {len(sites)}..."); print()
    found = 0
    for name, pat in sites.items():
        try:
            r = rhead(pat.format(nick), timeout=6)
            if r.status_code == 200:
                found += 1
                print(f"  {C.GREEN}✅{C.RESET} {name:15} {C.DIM}{pat.format(nick)}{C.RESET}")
                output.append(f"✅ {name}: {pat.format(nick)}")
            else: print(f"  {C.RED}❌{C.RESET} {name}")
        except: print(f"  {C.YELLOW}⚠{C.RESET}  {name}")
    print(); ok(f"Найдено: {found}/{len(sites)}")
    log_history("username", nick, f"{found}/{len(sites)}")
    ask_save("\n".join(output), f"username_{nick}")

def do_email():
    header(); result_header("EMAIL")
    if is_paranoia(): return
    email = prompt("Email")
    if "@" not in email: err("Неверный"); pause(); return
    local, dom = email.split("@", 1)
    output = []
    section("MX")
    try:
        for m in dns.resolver.resolve(dom, "MX"):
            v = str(m.exchange).rstrip("."); line("→", v); output.append(f"MX: {v}")
    except: warn("MX нет")
    section("A")
    try:
        for ip in dns.resolver.resolve(dom, "A"): line("→", str(ip))
    except: warn("A нет")
    section("GRAVATAR")
    h = hashlib.md5(email.lower().encode()).hexdigest()
    try:
        r = rhead(f"https://www.gravatar.com/avatar/{h}?d=404", timeout=8)
        if r.status_code == 200: ok("Есть")
        else: info("Нет")
    except: pass
    log_history("email", email)
    ask_save("\n".join(output), f"email_{local}")

def do_telegram():
    header(); result_header("TELEGRAM")
    if is_paranoia(): return
    nick = prompt("Ник").lstrip("@")
    if not nick: pause(); return
    output = []
    try:
        r = rget(f"https://t.me/{nick}")
        if r.status_code != 200: err("Не существует"); pause(); return
        html = r.text
        m = re.search(r'tgme_page_extra">([^<]+)<', html)
        if m: line("Инфо", m.group(1).strip()); output.append(f"Инфо: {m.group(1).strip()}")
        m = re.search(r'tgme_page_title[^>]*>([^<]+)<', html)
        if m: line("Название", m.group(1).strip())
        m = re.search(r'tgme_page_description[^>]*>([^<]+)<', html, re.DOTALL)
        if m:
            d = m.group(1).strip()
            if d: print(f"\n  {C.DIM}{d[:500]}{C.RESET}")
    except Exception as e: err(f"{e}")
    log_history("telegram", nick)
    ask_save("\n".join(output), f"tg_{nick}")

def do_discord():
    header(); result_header("DISCORD")
    did = prompt("ID")
    if not did.isdigit(): err("Число"); pause(); return
    try:
        uid = int(did); ts = ((uid >> 22) + 1420070400000) / 1000
        line("ID", did); line("Создан", datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"))
    except: pass
    log_history("discord", did); pause()

def do_steam():
    header(); result_header("STEAM")
    if is_paranoia(): return
    steam = prompt("SteamID64 или URL")
    if not steam: pause(); return
    output = []
    if not steam.isdigit():
        try:
            r = rget(f"https://steamcommunity.com/id/{steam}?xml=1")
            if r.status_code != 200: err("Не найден"); pause(); return
            xml = r.text
            for pat, lbl in [
                (r'<steamID64>(\d+)</steamID64>', "SteamID64"),
                (r'<steamID><!\[CDATA\[([^\]]+)\]\]></steamID>', "Ник"),
                (r'<onlineState>([^<]+)</onlineState>', "Статус"),
                (r'<memberSince>([^<]+)</memberSince>', "В Steam с"),
                (r'<realname><!\[CDATA\[([^\]]+)\]\]></realname>', "Имя"),
            ]:
                m = re.search(pat, xml)
                if m:
                    line(lbl, m.group(1)); output.append(f"{lbl}: {m.group(1)}")
                    if lbl == "SteamID64": steam = m.group(1)
        except: pass
    line("Профиль", f"https://steamcommunity.com/profiles/{steam}")
    log_history("steam", steam); ask_save("\n".join(output), f"steam_{steam}")

def do_ip():
    header(); result_header("IP")
    if is_paranoia(): return
    ip = prompt("IP")
    if not ip: pause(); return
    try:
        r = rget(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query,timezone,proxy,hosting,lat,lon")
        d = r.json()
        if d.get("status") != "success": err("?"); pause(); return
        for l, k in [("IP","query"),("Страна","country"),("Город","city"),
                     ("Провайдер","isp"),("ASN","as")]:
            line(l, d.get(k, "—"))
    except: pass
    log_history("ip", ip); pause()

def do_domain():
    header(); result_header("ДОМЕН")
    if is_paranoia(): return
    dom = prompt("Домен")
    if not dom: pause(); return
    try:
        w = python_whois.whois(dom)
        line("Регистратор", w.registrar or "—")
        line("Создан", str(w.creation_date) if w.creation_date else "—")
    except: pass
    section("DNS")
    for rt in ["A","MX","NS","TXT"]:
        try:
            for v in [str(r) for r in dns.resolver.resolve(dom, rt)][:5]:
                line(rt, v)
        except: pass
    log_history("domain", dom); pause()

def do_hash():
    header(); result_header("HASH")
    h = prompt("Хеш")
    if not h: pause(); return
    ln = len(h); ishex = all(c in "0123456789abcdefABCDEF" for c in h)
    types = []
    if ln==32 and ishex: types.append("MD5")
    if ln==40 and ishex: types.append("SHA-1")
    if ln==64 and ishex: types.append("SHA-256")
    if ln==128 and ishex: types.append("SHA-512")
    if ln==60 and h.startswith("$2"): types.append("bcrypt")
    line("Длина", str(ln)); line("Типы", ", ".join(types) if types else "?")
    pause()

def do_base64():
    header(); result_header("BASE64")
    print(f"  {C.GREEN}[1]{C.RESET} Кодировать  {C.GREEN}[2]{C.RESET} Декодировать")
    ch = prompt("Выбор")
    if ch == "1": line("→", base64.b64encode(prompt("Текст").encode()).decode())
    elif ch == "2":
        try: line("→", base64.b64decode(prompt("B64")).decode(errors="replace"))
        except: err("Ошибка")
    pause()

def do_myip():
    header(); result_header("МОЙ IP")
    if is_paranoia(): return
    try:
        ip = rget("https://api.ipify.org").text
        line("IP", ip)
        r = rget(f"http://ip-api.com/json/{ip}?fields=country,city,isp")
        d = r.json()
        line("Страна", d.get("country","—")); line("Провайдер", d.get("isp","—"))
    except: pass
    pause()

def do_ping():
    header(); result_header("PING")
    host = prompt("Хост")
    if not host: pause(); return
    try:
        ip = socket.gethostbyname(host); line("IP", ip)
        for _ in range(4):
            try:
                t0 = time.time()
                s = socket.socket(); s.settimeout(2); s.connect((ip, 80)); s.close()
                print(f"  {C.GREEN}✅ {(time.time()-t0)*1000:.0f}ms{C.RESET}")
            except: print(f"  {C.RED}❌ timeout{C.RESET}")
            time.sleep(0.3)
    except: pass
    pause()

def do_port():
    header(); result_header("ПОРТ")
    host = prompt("Хост"); ps = prompt("Порт")
    if not host or not ps: pause(); return
    try: ports = [int(ps)]
    except: err("Число"); pause(); return
    for p in ports:
        try:
            s = socket.socket(); s.settimeout(1)
            if s.connect_ex((host, p)) == 0: ok(f"{p} открыт")
            else: err(f"{p} закрыт")
            s.close()
        except: pass
    pause()

def do_qr():
    header(); result_header("QR")
    if is_paranoia(): return
    text = prompt("Текст")
    if not text: pause(); return
    try:
        url = f"https://api.qrserver.com/v1/create-qr-code/?size=400x400&data={requests.utils.quote(text)}"
        r = rget(url, timeout=15)
        if r.status_code == 200:
            fname = RESULTS_DIR / f"qr_{int(time.time())}.png"
            with open(fname, "wb") as f: f.write(r.content)
            ok(f"Сохранён: {fname}")
    except: pass
    pause()

def do_mac():
    header(); result_header("MAC")
    if is_paranoia(): return
    mac = prompt("MAC")
    mc = mac.replace(":","").replace("-","")[:6].upper()
    if len(mc) < 6: err("Неверный"); pause(); return
    try:
        r = rget(f"https://api.macvendors.com/{mc}")
        line("Производитель", r.text if r.status_code == 200 else "?")
    except: pass
    pause()

def do_vk():
    header(); result_header("VK")
    if is_paranoia(): return
    token = ""
    if os.path.exists(VK_TOKEN_FILE):
        try:
            with open(VK_TOKEN_FILE) as f: token = f.read().strip()
        except: pass
    if not token:
        warn("Нет токена (vk.com/dev)")
        t = prompt("Вставить? (y/n)")
        if t.lower() in ("y","yes","д","да"):
            tok = prompt("Токен")
            if tok:
                with open(VK_TOKEN_FILE, "w") as f: f.write(tok)
                ok("Сохранён")
        pause(); return
    nick = prompt("VK ID или ник")
    if not nick: pause(); return
    try:
        if not nick.isdigit():
            r = requests.get("https://api.vk.com/method/utils.resolveScreenName", params={
                "screen_name": nick, "access_token": token, "v": "5.199"}, timeout=10)
            d = r.json()
            if d.get("response"): nick = d["response"]["object_id"]
            else: err("Не найден"); pause(); return
        r = requests.get("https://api.vk.com/method/users.get", params={
            "user_ids": nick, "fields": "photo_max_orig,city,followers_count",
            "access_token": token, "v": "5.199"}, timeout=10)
        d = r.json()
        if d.get("response"):
            u = d["response"][0]
            line("Имя", f"{u.get('first_name','')} {u.get('last_name','')}")
            line("Город", u.get("city",{}).get("title","—"))
            line("Подписчиков", u.get("followers_count","—"))
    except Exception as e: err(f"{e}")
    pause()

def do_tiktok():
    header(); result_header("TIKTOK")
    if is_paranoia(): return
    nick = prompt("Ник").lstrip("@")
    if not nick: pause(); return
    try:
        r = requests.get(f"https://www.tiktok.com/@{nick}", headers={"User-Agent": UA}, timeout=15)
        if r.status_code != 200: err("Не найден"); pause(); return
        m = re.search(r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', r.text, re.DOTALL)
        if m:
            data = json.loads(m.group(1))
            detail = data.get("__DEFAULT_SCOPE__", {}).get("webapp.user-detail", {})
            stats = detail.get("userInfo", {}).get("stats", {})
            line("Подписчиков", stats.get("followerCount","—"))
            line("Лайков", stats.get("heartCount","—"))
            line("Видео", stats.get("videoCount","—"))
    except Exception as e: err(f"{e}")
    pause()

def do_whatsapp():
    header(); result_header("WHATSAPP")
    if is_paranoia(): return
    n = prompt("Номер")
    p, digits, e = parse_num(n)
    if e: err(e); pause(); return
    try:
        r = requests.get(f"https://wa.me/{digits}", headers={"User-Agent": UA}, timeout=10, allow_redirects=True)
        line("Зарегистрирован", "✅ да" if r.status_code == 200 else "❌ нет")
        m = re.search(r'<meta property="og:title" content="([^"]+)"', r.text)
        if m:
            name = m.group(1)
            if name not in ("WhatsApp", "Share on WhatsApp"):
                line("Имя", name); line("Бизнес", "✅ да")
    except: pass
    pause()

def do_subdomain():
    header(); result_header("ПОДДОМЕНЫ")
    if is_paranoia(): return
    dom = prompt("Домен")
    try:
        r = rget(f"https://crt.sh/?q=%25.{dom}&output=json", timeout=30)
        data = r.json()
        subs = set()
        for e in data:
            for n in e.get("name_value", "").split("\n"):
                n = n.strip().lower()
                if n and "*" not in n and n.endswith(dom): subs.add(n)
        subs = sorted(subs)
        ok(f"Найдено: {len(subs)}")
        for s in subs[:50]: print(f"  {s}")
    except Exception as e: err(f"{e}")
    pause()

def do_ssl():
    header(); result_header("SSL")
    if is_paranoia(): return
    dom = prompt("Домен")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((dom, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=dom) as ss:
                cert = ss.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", []))
        line("Издатель", issuer.get("organizationName","—"))
        line("До", cert.get("notAfter","—"))
    except: pass
    pause()

def do_dns():
    header(); result_header("DNS")
    if is_paranoia(): return
    dom = prompt("Домен")
    for rt in ["A","MX","NS","TXT","AAAA","CNAME"]:
        try:
            for v in [str(r) for r in dns.resolver.resolve(dom, rt)][:5]:
                line(rt, v)
        except: pass
    pause()

def do_headers():
    header(); result_header("HEADERS")
    if is_paranoia(): return
    url = prompt("URL")
    if not url.startswith(("http","https")): url = "https://" + url
    try:
        r = rget(url, allow_redirects=False)
        line("Статус", r.status_code)
        for k, v in list(r.headers.items())[:15]:
            line(k, v[:150])
    except: pass
    pause()

def do_robots():
    header(); result_header("ROBOTS")
    if is_paranoia(): return
    dom = prompt("Домен")
    if not dom.startswith(("http","https")): dom = "https://" + dom
    try:
        r = rget(f"{dom}/robots.txt")
        if r.status_code == 200:
            print(r.text[:2000])
    except: pass
    pause()

def do_wayback():
    header(); result_header("WAYBACK")
    if is_paranoia(): return
    dom = prompt("Домен")
    try:
        r = rget(f"https://archive.org/wayback/available?url={dom}")
        d = r.json()
        snap = d.get("archived_snapshots", {}).get("closest", {})
        if snap:
            line("Последний", snap.get("timestamp","—"))
            line("URL", snap.get("url","—"))
    except: pass
    pause()

# ═══ WEBHOOK ═══
def read_multiline():
    lines, empty = [], 0
    while True:
        try:
            l = input()
            if not l.strip():
                empty += 1
                if empty >= 2: break
                lines.append("")
            else:
                empty = 0; lines.append(l)
        except KeyboardInterrupt: break
    return "\n".join(lines).strip()

def do_webhook():
    w = {}
    if os.path.exists(WEBHOOK_FILE):
        try:
            with open(WEBHOOK_FILE) as f: w = json.load(f)
        except: pass
    while True:
        header(); result_header("WEBHOOK")
        print(f"  Discord: {C.GREEN if w.get('discord') else C.DIM}{'✓' if w.get('discord') else '—'}{C.RESET}")
        print(f"  Telegram: {C.GREEN if w.get('telegram_token') else C.DIM}{'✓' if w.get('telegram_token') else '—'}{C.RESET}\n")
        print(f"  {C.GREEN}[1]{C.RESET} Discord настройка")
        print(f"  {C.GREEN}[2]{C.RESET} Telegram настройка")
        print(f"  {C.GREEN}[3]{C.RESET} Удалить")
        print(f"  {C.GREEN}[4]{C.RESET} Отправить в Discord")
        print(f"  {C.GREEN}[5]{C.RESET} Отправить в Telegram")
        print(f"  {C.GREEN}[6]{C.RESET} Отправить в оба")
        print(f"  {C.DIM}[0]{C.RESET} Назад\n")
        ch = prompt("Выбор")
        if ch == "0": return
        elif ch == "1":
            url = prompt("Webhook URL")
            if url:
                w["discord"] = url
                with open(WEBHOOK_FILE,"w") as f: json.dump(w,f)
                ok("OK"); time.sleep(1)
        elif ch == "2":
            w["telegram_token"] = prompt("Токен")
            w["telegram_chat"] = prompt("Chat ID")
            with open(WEBHOOK_FILE,"w") as f: json.dump(w,f)
            ok("OK"); time.sleep(1)
        elif ch == "3":
            if os.path.exists(WEBHOOK_FILE): os.remove(WEBHOOK_FILE)
            w = {}; ok("Удалено"); time.sleep(1)
        elif ch == "4":
            if not w.get("discord"): err("Не настроен"); time.sleep(1); continue
            header(); result_header("СООБЩЕНИЕ В DISCORD")
            print(f"{C.DIM}Две пустые строки — конец.{C.RESET}\n")
            text = read_multiline()
            if text:
                try:
                    requests.post(w["discord"], json={"content": text[:1900]}, timeout=10)
                    ok("Отправлено")
                except: err("Ошибка")
            pause()
        elif ch == "5":
            if not w.get("telegram_token"): err("Не настроен"); time.sleep(1); continue
            header(); result_header("СООБЩЕНИЕ В TELEGRAM")
            text = read_multiline()
            if text:
                try:
                    requests.post(f"https://api.telegram.org/bot{w['telegram_token']}/sendMessage",
                        json={"chat_id": w["telegram_chat"], "text": text[:4000], "parse_mode": "Markdown"}, timeout=10)
                    ok("Отправлено")
                except: err("Ошибка")
            pause()
        elif ch == "6":
            header(); result_header("В ОБА")
            text = read_multiline()
            if text:
                if w.get("discord"):
                    try:
                        requests.post(w["discord"], json={"content": text[:1900]}, timeout=10)
                        ok("Discord ✅")
                    except: err("Discord ошибка")
                if w.get("telegram_token"):
                    try:
                        requests.post(f"https://api.telegram.org/bot{w['telegram_token']}/sendMessage",
                            json={"chat_id": w["telegram_chat"], "text": text[:4000], "parse_mode": "Markdown"}, timeout=10)
                        ok("Telegram ✅")
                    except: err("TG ошибка")
            pause()

def do_proxy():
    header(); result_header("ПРОКСИ")
    print(f"  Статус: {C.GREEN if CONFIG.get('use_proxy') else C.RED}{'ВКЛ' if CONFIG.get('use_proxy') else 'ВЫКЛ'}{C.RESET}")
    print(f"  URL: {CONFIG.get('proxy_url')}\n")
    print(f"  {C.GREEN}[1]{C.RESET} Tor включить")
    print(f"  {C.GREEN}[2]{C.RESET} Выключить")
    print(f"  {C.GREEN}[3]{C.RESET} Свой прокси")
    print(f"  {C.DIM}[0]{C.RESET} Назад\n")
    ch = prompt("Выбор")
    if ch == "1":
        CONFIG["use_proxy"] = True; save_config()
        CONFIG["proxy_url"] = "socks5h://127.0.0.1:9050"
        ok("Tor ВКЛ"); time.sleep(1)
    elif ch == "2":
        CONFIG["use_proxy"] = False; save_config(); ok("ВЫКЛ"); time.sleep(1)
    elif ch == "3":
        p = prompt("URL")
        if p:
            CONFIG["proxy_url"] = p; CONFIG["use_proxy"] = True
            save_config(); ok("OK"); time.sleep(1)

def do_paranoia():
    header(); result_header("ПАРАНОЙЯ")
    cur = CONFIG.get("paranoia", False)
    print(f"  Статус: {C.RED if cur else C.GREEN}{'ВКЛ' if cur else 'ВЫКЛ'}{C.RESET}\n")
    print(f"  {C.GREEN}[1]{C.RESET} Включить")
    print(f"  {C.GREEN}[2]{C.RESET} Выключить\n")
    ch = prompt("Выбор")
    if ch == "1": CONFIG["paranoia"] = True; save_config(); warn("ВКЛ"); time.sleep(1.5)
    elif ch == "2": CONFIG["paranoia"] = False; save_config(); ok("ВЫКЛ"); time.sleep(1)

def show_history():
    header(); result_header("ИСТОРИЯ")
    h = load_history()
    if not h: info("Пусто"); pause(); return
    for i, e in enumerate(h[:30], 1):
        print(f"  {C.CYAN}[{i}]{C.RESET} {C.DIM}{e['timestamp']}{C.RESET}")
        print(f"       {e['command']} → {e['target']}")
    ch = input(f"\n{C.YELLOW}Очистить? [y/N]: {C.RESET}").strip().lower()
    if ch in ("y","yes","д","да"): save_history([]); ok("Очищено"); time.sleep(1)

# ═══ МЕНЮ ═══
def show_menu():
    print(f"{C.CYAN}╔══════════════════════════════════════════════════════════╗{C.RESET}")
    print(f"{C.CYAN}║{C.RESET}  {C.BOLD}{C.WHITE}ТЕЛЕФОН И ЛЮДИ{C.RESET}                                          {C.CYAN}║{C.RESET}")
    print(f"{C.CYAN}╚══════════════════════════════════════════════════════════╝{C.RESET}")
    print(f"  {C.GREEN}[ 1]{C.RESET} Номер {C.DIM}(маленький){C.RESET}")
    print(f"  {C.GREEN}[ 2]{C.RESET} Номер {C.RED}{C.BOLD}(БОЛЬШОЙ ДОКС){C.RESET}")
    print(f"  {C.GREEN}[ 3]{C.RESET} Ник (21 соцсеть)")
    print(f"  {C.GREEN}[ 4]{C.RESET} Email")
    print(f"  {C.GREEN}[ 5]{C.RESET} Telegram по нику")
    print(f"  {C.GREEN}[ 6]{C.RESET} Telegram по номеру {C.YELLOW}NEW{C.RESET}")
    print(f"  {C.GREEN}[ 7]{C.RESET} Viber Check {C.YELLOW}NEW{C.RESET}")
    print(f"  {C.GREEN}[ 8]{C.RESET} Signal Check {C.YELLOW}NEW{C.RESET}")
    print(f"  {C.GREEN}[ 9]{C.RESET} WhatsApp бизнес")
    print(f"  {C.GREEN}[10]{C.RESET} Twitter {C.YELLOW}NEW{C.RESET}")
    print(f"  {C.GREEN}[11]{C.RESET} Discord ID")
    print(f"  {C.GREEN}[12]{C.RESET} Steam")
    print(f"  {C.GREEN}[13]{C.RESET} VK")
    print(f"  {C.GREEN}[14]{C.RESET} TikTok")
    print()
    print(f"{C.CYAN}╔══════════════════════════════════════════════════════════╗{C.RESET}")
    print(f"{C.CYAN}║{C.RESET}  {C.BOLD}{C.WHITE}СЕТЬ И ДОМЕНЫ{C.RESET}                                           {C.CYAN}║{C.RESET}")
    print(f"{C.CYAN}╚══════════════════════════════════════════════════════════╝{C.RESET}")
    print(f"  {C.GREEN}[15]{C.RESET} IP")
    print(f"  {C.GREEN}[16]{C.RESET} Домен")
    print(f"  {C.GREEN}[17]{C.RESET} Поддомены")
    print(f"  {C.GREEN}[18]{C.RESET} SSL")
    print(f"  {C.GREEN}[19]{C.RESET} DNS")
    print(f"  {C.GREEN}[20]{C.RESET} HTTP-заголовки")
    print(f"  {C.GREEN}[21]{C.RESET} robots.txt")
    print(f"  {C.GREEN}[22]{C.RESET} Wayback")
    print(f"  {C.GREEN}[23]{C.RESET} VirusTotal {C.YELLOW}NEW{C.RESET}")
    print()
    print(f"{C.CYAN}╔══════════════════════════════════════════════════════════╗{C.RESET}")
    print(f"{C.CYAN}║{C.RESET}  {C.BOLD}{C.WHITE}УТИЛИТЫ{C.RESET}                                                  {C.CYAN}║{C.RESET}")
    print(f"{C.CYAN}╚══════════════════════════════════════════════════════════╝{C.RESET}")
    print(f"  {C.GREEN}[24]{C.RESET} Тип хеша")
    print(f"  {C.GREEN}[25]{C.RESET} QR-код")
    print(f"  {C.GREEN}[26]{C.RESET} MAC")
    print(f"  {C.GREEN}[27]{C.RESET} Base64")
    print(f"  {C.GREEN}[28]{C.RESET} Порт")
    print(f"  {C.GREEN}[29]{C.RESET} Ping")
    print(f"  {C.GREEN}[30]{C.RESET} Мой IP")
    print()
    print(f"{C.CYAN}╔══════════════════════════════════════════════════════════╗{C.RESET}")
    print(f"{C.CYAN}║{C.RESET}  {C.BOLD}{C.WHITE}СИСТЕМА{C.RESET}                                                  {C.CYAN}║{C.RESET}")
    print(f"{C.CYAN}╚══════════════════════════════════════════════════════════╝{C.RESET}")
    print(f"  {C.YELLOW}[H]{C.RESET} История")
    print(f"  {C.YELLOW}[M]{C.RESET} Мониторинг {C.YELLOW}NEW{C.RESET}")
    print(f"  {C.YELLOW}[L]{C.RESET} Логи запросов {C.YELLOW}NEW{C.RESET}")
    print(f"  {C.YELLOW}[X]{C.RESET} Прокси")
    print(f"  {C.YELLOW}[W]{C.RESET} Webhook")
    print(f"  {C.RED}[!]{C.RESET} Паранойя")
    print(f"  {C.RED}[0]{C.RESET} Выход")
    print()
    print(f"{C.CYAN}══════════════════════════════════════════════════════════{C.RESET}")

def route(ch):
    return {
        "1": do_phone_small, "2": do_phone_big, "3": do_username,
        "4": do_email, "5": do_telegram, "6": do_tg_by_phone,
        "7": do_viber_check, "8": do_signal_check,
        "9": do_whatsapp, "10": do_twitter_search,
        "11": do_discord, "12": do_steam, "13": do_vk, "14": do_tiktok,
        "15": do_ip, "16": do_domain, "17": do_subdomain,
        "18": do_ssl, "19": do_dns, "20": do_headers,
        "21": do_robots, "22": do_wayback, "23": do_virustotal,
        "24": do_hash, "25": do_qr, "26": do_mac, "27": do_base64,
        "28": do_port, "29": do_ping, "30": do_myip,
        "h": show_history, "m": do_monitor, "l": show_logs,
        "x": do_proxy, "w": do_webhook, "!": do_paranoia,
    }.get(ch.lower())

def main():
    while True:
        header(); show_menu()
        print()
        ch = input(f"{C.GREEN}┌─[{C.WHITE}there@osint{C.GREEN}]-[{C.CYAN}~{C.GREEN}]\n└──╼ {C.RESET}").strip()
        if ch == "0":
            clear(); print(f"{C.CYAN}Пока, DEK0.{C.RESET}\n"); break
        action = route(ch)
        if action:
            try: action()
            except KeyboardInterrupt: print(f"\n{C.YELLOW}Прервано{C.RESET}"); time.sleep(1)
            except Exception as e:
                err(f"Ошибка: {e}")
                import traceback; traceback.print_exc()
                pause()
        else:
            warn("Неизвестная команда"); time.sleep(1)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print(f"\n{C.CYAN}Выход{C.RESET}"); sys.exit(0)
    except Exception:
        import traceback; traceback.print_exc()
        input("\n[Enter чтобы закрыть]")