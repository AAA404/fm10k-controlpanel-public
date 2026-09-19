import type { PortTelemetry } from './types'

// Compare device timestamps with the device clock, then advance with browser
// monotonic time. Workstation clock skew must not turn valid samples stale.
export function advanceSampleClock(serverTime: number|null, receivedAt: number, monotonicNow: number) {
  return serverTime !== null && Number.isFinite(serverTime)
    ? serverTime + Math.max(0, monotonicNow - receivedAt) / 1000 : null
}

function elapsedLabel(seconds: number) {
  if (seconds < 60) return Math.floor(seconds)+' 秒'
  if (seconds < 3600) return Math.floor(seconds/60)+' 分钟'
  return Math.floor(seconds/3600)+' 小时'
}

export function portFreshness(port: PortTelemetry|undefined, sampleNow: number|null, staleAfter = 3, error?: string|null) {
  const sampled = !!port && Number.isFinite(port.sampled_at) && port.sampled_at > 0
  const age = sampled && sampleNow !== null ? Math.max(0, sampleNow - port!.sampled_at) : null
  const delayed = !!error || port?.quality === 'stale' || (age !== null && age > staleAfter)
  const previous = sampled ? '链路与收发统计保留上次结果。' : '尚未取得端口遥测。'
  if (error) return {age, delayed, tone:'warning', label:'更新失败', description:'本次遥测读取失败，正在等待重试。'+previous}
  if (!sampled) return {age, delayed:false, tone:'muted', label:'等待采样', description:'尚未取得这个端口的遥测，链路和计数器暂不可用。'}
  if (delayed) return {age, delayed, tone:'warning', label:age !== null && age > staleAfter ? elapsedLabel(age)+'未更新' : '采样延迟',
    description:age !== null && age > staleAfter ? '距最近一次采样已超过 '+staleAfter+' 秒。'+previous : '数据源未能及时更新端口快照。'+previous}
  if (port!.state_quality === 'unavailable' || port!.state_quality === 'pending')
    return {age, delayed:false, tone:'warning', label:'状态未取得', description:'本次未取得有效的端口状态，当前链路状态无法确认。'}
  if (port!.counter_quality === 'unavailable' || port!.counter_quality === 'pending')
    return {age, delayed:false, tone:'warning', label:'统计未取得', description:'端口状态已读取，收发计数器暂不可用。缺失计数显示为“不可用”。'}
  if (port!.quality === 'unavailable' || port!.quality === 'pending')
    return {age, delayed:false, tone:'warning', label:'采样不可用', description:'本次未取得有效的端口遥测，不能据此判断链路故障。'}
  return {age, delayed:false, tone:'normal', label:age === null ? '采样时间待核实' : '采样正常',
    description:(port!.quality === 'simulated' ? '当前为模拟采样。' : '端口采样正常。')+'链路状态与收发统计来自最近一次采样。'}
}

export function portLinkLabel(port: PortTelemetry|undefined, delayed = false) {
  if (!port) return '未取得'
  if (!port.active) return '合口占用'
  const label = port.degraded ? '故障关闭' :
    ['unavailable','pending'].includes(port.state_quality || port.quality) || !['up','down'].includes(port.link) ? '未知' :
    port.link === 'up' ? '已连接' : '未连接'
  return delayed && label !== '未知' ? '上次：'+label : label
}
