"""Human-readable review of EPL topology and its VLAN side effects."""
from .models import PHYSICAL, SwitchConfiguration


def vlan_description(port):
    parts = ([f"Native {port.pvid}"] if port.pvid is not None else [])
    if port.tagged_vlans:
        parts.append("Tagged " + ", ".join(map(str, port.tagged_vlans)))
    return " · ".join(parts) or "未加入 VLAN"


def backup_description(group):
    if group.split_vlan_backup is None:
        return "无恢复记录"
    base = PHYSICAL[group.epl]["base"]
    return "; ".join(f"P{base + lane}：{vlan_description(port)}（{'启用' if port.enabled else '关闭'}）"
                     for lane, port in enumerate(group.split_vlan_backup))


def group_changes(before: SwitchConfiguration, after: SwitchConfiguration):
    old = {group.epl: group for group in before.groups}
    changes = []
    existing = {vlan.id for vlan in after.vlans}
    for group in after.groups:
        previous = old[group.epl]
        if group.mode == previous.mode:
            continue
        base = PHYSICAL[group.epl]["base"]
        rows = []
        for port in range(base, base + 4):
            a, b = before.ports[port], after.ports[port]
            rows.append({"port": port, "before": vlan_description(a), "after": vlan_description(b),
                         "was_active": port in previous.active_ports(), "active": port in group.active_ports(),
                         "enabled_before": a.enabled, "enabled_after": b.enabled})
        notes = []
        if previous.mode == "split" and group.split_vlan_backup is not None:
            notes.append(f"确认配置后将保存 P{base}–P{base + 3} 的拆分 VLAN 和启用状态，再次拆分时恢复。")
        if group.mode == "split" and previous.split_vlan_backup is not None:
            notes.append("恢复各端口合并前的 VLAN 和启用状态。")
            for lane, port in enumerate(previous.split_vlan_backup):
                missing = ({port.pvid, *port.tagged_vlans} - {None}) - existing
                if missing:
                    notes.append(f"P{base + lane} 原 VLAN {', '.join(map(str, sorted(missing)))} 已删除，"
                                 "跳过这些成员关系；没有剩余 VLAN 的端口保持关闭。")
        elif group.mode == "split":
            notes.append("此 EPL 没有拆分恢复记录；新子口保持关闭，请配置 VLAN 后启用。")
        changes.append({"epl": group.epl, "before_mode": previous.mode, "after_mode": group.mode,
                        "ports": rows, "notes": notes})
    return changes


def configuration_changes(before: SwitchConfiguration, after: SwitchConfiguration, diff):
    """Keep raw values for normal fields without dumping dormant history JSON."""
    a, b = before.model_dump(mode="json"), after.model_dump(mode="json")
    a.pop("groups"); b.pop("groups")
    changes = diff(a, b)
    old = {group.epl: group for group in before.groups}
    for group in after.groups:
        previous = old[group.epl]
        for field, label in (("mode", "模式"), ("lane_speeds", "Lane 速率")):
            start, end = getattr(previous, field), getattr(group, field)
            if start != end:
                changes.append({"path": f"/groups/{group.epl}/{field}", "label": f"EPL {group.epl} · {label}",
                                "before": start, "after": end})
        if previous.split_vlan_backup != group.split_vlan_backup:
            changes.append({"path": f"/groups/{group.epl}/split_vlan_backup",
                            "label": f"EPL {group.epl} · 拆分 VLAN 恢复记录",
                            "before": backup_description(previous), "after": backup_description(group)})
    labels = {"enabled": "管理启用", "pvid": "PVID / Native VLAN", "tagged_vlans": "Tagged VLAN",
              "vlan_mode": "VLAN 模式", "ingress_filtering": "入口 VLAN 过滤"}
    for change in changes:
        path = change["path"].strip("/").split("/")
        if len(path) >= 3 and path[:2] == ["qos", "roce"]:
            names = {"enabled": "启用", "ports": "参与端口", "priority": "无损优先级",
                     "mode": "模式", "classification": "优先级分类", "dscp": "数据 DSCP",
                     "cnp_dscp": "CNP DSCP", "dcbx": "DCBX 策略交换",
                     "cable_length_m": "最长线缆（米）", "response_time_ns": "暂停响应上限（纳秒）"}
            change["label"] = "RoCE · " + names.get(path[2], path[2])
        if len(path) == 3 and path[0] == "ports" and path[2] in labels:
            change["label"] = f"P{path[1]} · {labels[path[2]]}"
    return changes
