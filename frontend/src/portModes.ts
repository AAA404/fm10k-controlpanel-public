import type { Configuration, PortConfig, PortGroup, SplitVlanBackup } from './types'

export const groupBase = (group: PortGroup) => [0,1,2,5,6,7].indexOf(group.epl)*4+1
export const vlanMembers = (port: SplitVlanBackup) => [...new Set([
  ...(port.pvid === null ? [] : [port.pvid]), ...port.tagged_vlans,
])].sort((a,b) => a-b)
export const vlanDescription = (port: SplitVlanBackup) => [
  port.pvid === null ? '' : 'Native '+port.pvid,
  port.tagged_vlans.length ? 'Tagged '+port.tagged_vlans.join(', ') : '',
].filter(Boolean).join(' · ') || '未加入 VLAN'

function capture(port: PortConfig): SplitVlanBackup {
  return {enabled:port.enabled,vlan_mode:port.vlan_mode,pvid:port.pvid,
    tagged_vlans:[...port.tagged_vlans],ingress_filtering:port.ingress_filtering}
}

/** Mutate only this EPL's mode and VLAN/admin fields in the page draft. */
export function changeGroupMode(configuration: Configuration, group: PortGroup, mode: PortGroup['mode']) {
  if (group.mode === mode) return
  const base = groupBase(group), ports = [0,1,2,3].map(lane => configuration.ports[base+lane]!)
  if (group.mode === 'split' && mode !== 'split') {
    const backup = ports.map(capture)
    group.split_vlan_backup = backup
    const common = vlanMembers(backup[0]!).filter(vid => backup.every(port => vlanMembers(port).includes(vid)))
    const main = ports[0]!
    // Keep the primary port's tag/native convention for the common VLANs.
    // With no intersection, retain its existing profile and show the removals.
    if (common.length) {
      main.pvid = main.pvid !== null && common.includes(main.pvid) ? main.pvid : null
      main.tagged_vlans = common.filter(vid => vid !== main.pvid)
      main.vlan_mode = main.tagged_vlans.length ? 'trunk' : backup[0]!.vlan_mode
    }
    main.enabled = backup.some(port => port.enabled) && vlanMembers(main).length > 0
    for (const port of ports.slice(1)) Object.assign(port,{enabled:false,pvid:null,tagged_vlans:[]})
  } else if (mode === 'split') {
    const backup = group.split_vlan_backup
    if (backup?.length === 4) {
      const existing = new Set(configuration.vlans.map(vlan => vlan.id))
      ports.forEach((port,lane) => {
        const saved = backup[lane]!
        const pvid = saved.pvid !== null && existing.has(saved.pvid) ? saved.pvid : null
        const tagged = saved.tagged_vlans.filter(vid => existing.has(vid))
        Object.assign(port,{...saved,pvid,tagged_vlans:tagged,
          enabled:saved.enabled && (pvid !== null || tagged.length > 0)})
      })
      delete group.split_vlan_backup
    } else {
      // Existing merged configurations have no historical split profile.
      for (const port of ports.slice(1)) port.enabled = false
    }
  }
  group.mode = mode
}

export function inactiveReferences(configuration: Configuration, group: PortGroup): string[] {
  if (group.mode === 'split') return []
  const messages: string[] = [], base = groupBase(group)
  for (let id = base+1; id <= base+3; id++) {
    const port = configuration.ports[id]!, refs = []
    if (port.edge || port.bpdu_guard || port.path_cost) refs.push('RSTP')
    if (port.ingress_kbps || port.egress_kbps || Object.values(port.storm).some(Boolean)) refs.push('流量策略')
    for (const lag of configuration.lags.filter(lag => lag.members.includes(id))) refs.push(lag.name)
    if (configuration.static_macs.some(mac => mac.port === id)) refs.push('静态 MAC')
    if (configuration.mirror.enabled && [configuration.mirror.source,configuration.mirror.destination].includes(id)) refs.push('镜像')
    if (configuration.igmp.router_ports.includes(id) || configuration.igmp.fast_leave_ports.includes(id) ||
        configuration.igmp.static_groups.some(group => group.ports.includes(id))) refs.push('IGMP')
    if (refs.length) messages.push('P'+id+'：'+refs.join('、'))
  }
  return messages
}
