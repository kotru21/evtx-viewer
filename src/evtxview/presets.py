"""Пресеты анализа — готовые представления под конкретные задачи DFIR.

Каждый пресет принимает уже отобранные записи (EventRecord) и печатает свой вид.
Регистрируются в PRESETS; выбираются флагом --preset.
"""

import os

from evtxview.render import C
from evtxview.util import to_local


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


PRESETS = {
    'process-tree': process_tree,
}
