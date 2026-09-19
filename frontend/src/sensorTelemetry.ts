// Sensor timestamps and sampleNow must both use the device clock.
export function sensorQuality(quality: string | undefined, sampledAt: number | null | undefined, sampleNow: number | null) {
  const state = quality ?? 'pending'
  if (!['valid', 'simulated'].includes(state)) return state
  if (sampledAt == null || !Number.isFinite(sampledAt) || sampledAt <= 0 || sampleNow === null) return 'pending'
  return sampleNow - sampledAt > 15 ? 'stale' : state
}
