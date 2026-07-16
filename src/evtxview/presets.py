"""Пресеты анализа — готовые представления под конкретные задачи DFIR.

Каждый пресет принимает уже отобранные записи (EventRecord) и печатает свой вид.
Регистрируются в PRESETS; выбираются флагом --preset.
"""

import os
from collections import defaultdict
from datetime import timedelta

from evtxview.render import C
from evtxview.util import parse_utc, to_local


def _proc_label(rec, tz):
    """Строка узла дерева: время, образ (basename), PID, командная строка."""
    img = rec.data.get('Image', '?')
    name = os.path.basename(img) or img
    pid = rec.data.get('ProcessId', '?')
    cmd = rec.data.get('CommandLine', '')
    t = to_local(rec.utc, tz)[11:19]  # HH:MM:SS
    label = f"{C.DIM}{t}{C.X}  {C.CY}{name}{C.X} ({pid})"
    if cmd:
        if len(cmd) > 90:
            cmd = cmd[:87] + '...'
        label += f"  {C.DIM}{cmd}{C.X}"
    return label


def process_tree(records, tz):
    """Дерево процессов из Sysmon EID 1 (ProcessCreate) по ProcessGuid → ParentProcessGuid.

    Процессы, чей родитель не захвачен в выборке, — корни леса. Порядок детей — по времени.
    """
    procs = [r for r in records if r.eid == '1' and r.data.get('ProcessGuid')]
    if not procs:
        print("  Нет событий Sysmon EID 1 (ProcessCreate) в выборке.")
        return

    by_guid = {r.data['ProcessGuid']: r for r in procs}
    children = {}
    for r in procs:
        children.setdefault(r.data.get('ParentProcessGuid', ''), []).append(r)
    for kids in children.values():
        kids.sort(key=lambda r: r.utc)

    roots = sorted(
        (r for r in procs if r.data.get('ParentProcessGuid') not in by_guid),
        key=lambda r: r.utc,
    )
    print(f"{C.BOLD}Дерево процессов (Sysmon EID 1){C.X}: "
          f"{len(procs)} процессов, {len(roots)} корней\n")

    visited = set()

    def walk(rec, prefix, is_last, top):
        guid = rec.data.get('ProcessGuid')
        connector = '' if top else ('└─ ' if is_last else '├─ ')
        print(prefix + connector + _proc_label(rec, tz))
        if guid in visited:  # защита от повторного GUID (переиспользование)
            return
        visited.add(guid)
        kids = children.get(guid, [])
        child_prefix = prefix + ('' if top else ('   ' if is_last else '│  '))
        for i, kid in enumerate(kids):
            walk(kid, child_prefix, i == len(kids) - 1, top=False)

    for root in roots:
        walk(root, '', True, top=True)


LOGON_TYPE_NAMES = {
    '2': 'Interactive', '3': 'Network', '4': 'Batch', '5': 'Service',
    '7': 'Unlock', '8': 'NetworkCleartext', '9': 'NewCredentials',
    '10': 'RemoteInteractive(RDP)', '11': 'CachedInteractive',
}

BRUTE_FORCE_THRESHOLD = 5      # неудачных входов
BRUTE_FORCE_WINDOW = timedelta(minutes=5)


def _account_key(rec):
    domain = rec.data.get('TargetDomainName', '')
    name = rec.data.get('TargetUserName') or '?'
    return f"{domain}\\{name}" if domain and domain != '-' else name


def _fmt_duration(delta):
    total = int(delta.total_seconds())
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


def _logon_type_label(rec):
    lt = rec.data.get('LogonType', '?')
    return LOGON_TYPE_NAMES.get(lt, lt)


def _detect_brute_force(failures):
    """Серия неудачных входов по одной учётке или одному IP в коротком окне."""
    for key_fn, label in (
        (_account_key, 'учётной записи'),
        (lambda r: r.data.get('IpAddress') or '-', 'IP-адресу'),
    ):
        buckets = defaultdict(list)
        for r in failures:
            dt = parse_utc(r.utc)
            if dt:
                buckets[key_fn(r)].append(dt)
        for key, times in buckets.items():
            times.sort()
            window = []
            for t in times:
                window.append(t)
                window = [w for w in window if t - w <= BRUTE_FORCE_WINDOW]
                if len(window) >= BRUTE_FORCE_THRESHOLD:
                    print(f"  {C.R}⚠ Возможный brute-force по {label} {key}: "
                          f"{len(window)} неудачных входов за "
                          f"{int(BRUTE_FORCE_WINDOW.total_seconds() // 60)} мин "
                          f"({window[0].strftime('%H:%M:%S')}..{window[-1].strftime('%H:%M:%S')}){C.X}")
                    break


def logon_analysis(records, tz):
    """Успешные/неуспешные входы (Security 4624/4625/4634/4648/4672) по учётным
    записям: сессии (пары 4624→4634 по TargetLogonId) с длительностью,
    привилегированные входы (4672), список неудач и признаки brute-force.
    """
    logons = [r for r in records if r.eid == '4624']
    failures = [r for r in records if r.eid == '4625']
    if not logons and not failures:
        print("  Нет событий входа (Security EID 4624/4625) в выборке.")
        return

    logoffs = {r.data.get('TargetLogonId'): r for r in records if r.eid == '4634'}
    privileged_ids = {r.data.get('SubjectLogonId') for r in records if r.eid == '4672'}

    print(f"{C.BOLD}Анализ входов (Security){C.X}: "
          f"{len(logons)} успешных, {len(failures)} неуспешных\n")

    by_account = defaultdict(list)
    for r in logons:
        by_account[_account_key(r)].append(r)

    for account in sorted(by_account):
        sessions = sorted(by_account[account], key=lambda r: r.utc)
        print(f"{C.CY}{account}{C.X}  ({len(sessions)} вход(ов))")
        for r in sessions:
            logon_id = r.data.get('TargetLogonId')
            ip = r.data.get('IpAddress') or '-'
            t_on = to_local(r.utc, tz)
            priv = f"  {C.Y}[privileged: 4672]{C.X}" if logon_id in privileged_ids else ''
            logoff = logoffs.get(logon_id)
            if logoff:
                dt_on, dt_off = parse_utc(r.utc), parse_utc(logoff.utc)
                dur = _fmt_duration(dt_off - dt_on) if dt_on and dt_off else '?'
                print(f"    {C.DIM}{t_on}{C.X} -> {to_local(logoff.utc, tz)[11:]}  "
                      f"({dur})  LogonType={_logon_type_label(r)}  IP={ip}{priv}")
            else:
                print(f"    {C.DIM}{t_on}{C.X} -> {C.Y}нет парного 4634 (сессия ещё "
                      f"открыта или лог обрезан){C.X}  LogonType={_logon_type_label(r)}  "
                      f"IP={ip}{priv}")
        print()

    if failures:
        print(f"{C.R}Неуспешные входы:{C.X}")
        for r in sorted(failures, key=lambda r: r.utc):
            ip = r.data.get('IpAddress') or '-'
            print(f"    {C.DIM}{to_local(r.utc, tz)}{C.X}  {_account_key(r)}  "
                  f"IP={ip}  LogonType={_logon_type_label(r)}")
        print()
        _detect_brute_force(failures)


PRESETS = {
    'process-tree': process_tree,
    'logon-analysis': logon_analysis,
}
