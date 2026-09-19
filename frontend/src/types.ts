export interface SplitVlanBackup {
  enabled: boolean; vlan_mode: 'access'|'trunk'; pvid: number|null;
  tagged_vlans: number[]; ingress_filtering: boolean;
}
export interface PortGroup {
  epl: number; mode: '100g'|'40g'|'split'; lane_speeds: number[];
  split_vlan_backup?: SplitVlanBackup[]|null;
}
export interface PortConfig {
  name: string; enabled: boolean; mtu: number; vlan_mode: 'access'|'trunk'; pvid: number|null;
  tagged_vlans: number[]; ingress_filtering: boolean; edge: boolean; bpdu_guard: boolean;
  path_cost: number; port_priority: number; lldp: boolean; direct_receiver: boolean;
  storm: { broadcast_kbps: number; multicast_kbps: number; unknown_unicast_kbps: number };
  ingress_kbps: number; egress_kbps: number;
}
export interface FanCurve {
  sensor: string; idle_temperature_c: number; load_temperature_c: number; critical_temperature_c: number;
  idle_speed_percent: number; load_speed_percent: number; hysteresis_c: number; response_time_s: number;
}
export interface RoceConfig {
  enabled: boolean; ports: number[]; priority: 3; cable_length_m: number; response_time_ns: number;
  mode: 'static-pfc'; classification: 'pcp'|'dscp'; dscp: number; cnp_dscp: number; dcbx: 'off'|'ieee';
  watchdog: {enabled:boolean; detect_ms:number; recovery_ms:number; cooldown_ms:number};
}
export interface Configuration {
  schema_version: number; profile: string; groups: PortGroup[]; ports: Record<string, PortConfig>;
  vlans: { id: number; name: string }[];
  lags: { name: string; members: number[]; mode: string; minimum_links: number; periodic: string }[];
  static_macs: { mac: string; vlan: number; port: number }[]; mac_aging_seconds: number;
  rstp: { enabled: boolean; bridge_priority: number };
  lldp: { enabled: boolean; transmit_interval: number; hold_multiplier: number };
  igmp: { enabled: boolean; vlans: number[]; router_ports: number[]; fast_leave_ports: number[]; membership_timeout: number; static_groups: { address: string; vlan: number; ports: number[] }[] };
  qos: { trust: string; default_priority: number; priority_map: number[]; scheduler: string; weights: number[]; roce: RoceConfig };
  mirror: { enabled: boolean; source: number|null; destination: number|null; direction: string };
  fan: FanCurve;
}
export interface PortTelemetry {
  id: number; epl: number; mpo: number; lane: number; active: boolean; enabled: boolean; name: string;
  speed_gbps: number|null; scheduler_speed_gbps?: number|null; link: string; quality: string;
  rx_bytes: number|null; tx_bytes: number|null; crc_errors: number|null;
  sampled_at: number; degraded: boolean; counter_epoch: number|null;
  ethernet_mode?: string; sample_generation?: string; state_quality?: string; counter_quality?: string;
  rx_packets?: number|null; tx_packets?: number|null; rx_errors?: number|null; tx_errors?: number|null;
  rx_drops?: number|null; tx_drops?: number|null;
}
export interface Job { id: string; kind: string; state: string; message: string; error?: string; deadline?: number; remaining_seconds?: number; rollback_failed?: boolean }

export interface OpticalLane {
  lane:number; tx_ready:boolean|null; rx_ready:boolean|null; rx_idle:boolean|null; rx_activity:boolean|null;
  tx_power_dbm:number|null; rx_power_dbm:number|null; eye_height_mv:number|null; eye_width_ui:number|null;
  coarse_dfe:number|null; fine_dfe:number|null; dfe_mode:number|null;
  tx_pre:number|null; tx_cursor:number|null; tx_post:number|null;
  rx_polarity:number|null; tx_polarity:number|null; rx_termination:number|null;
  signal_transition_threshold:number|null; serdes_raw:string|null;
}
export interface OpticalSnapshot {
  port:number; epl:number; mpo:number; owner_port:number; mode:PortGroup['mode']|null; profile:string|null; revision:number|null;
  server_time:number; refreshing:boolean; refresh_seconds:number; stale_after_seconds:number;
  capabilities:Record<string,string>;
  phy:{quality:string; sampled_at:number|null; reason?:string; error?:string; source?:string; errors?:Record<string,string|number>;
    lanes:OpticalLane[]; pcs:{block_lock:(boolean|null)[]; am_lock:(boolean|null)[]; aligned:boolean|null; high_ber:boolean|null; raw:string|null}|null};
}

export interface EyeScan {
  id?:string; state:string; source:string; port:number; epl:number; lane:number; speed_mbps:number;
  signal_source:'external'|'internal_prbs31_loopback';
  temporary_master?:boolean; sampling_master_firmware?:number;
  x_points:number; y_points:number; x_resolution:number; x_step?:number; y_step:number; y_min:number;
  dwell_bits:number; columns_done:number; received_columns?:number; progress?:number;
  started_at:number; elapsed_ms:number; restored:boolean; restore_failed:boolean; error?:string; message?:string;
  errors:number[][]; firmware?:number; master_firmware?:number; protocol?:number;
  metrics?:{threshold:number; center_errors:number; sampled_bits:number; center_error_ratio:number;
    detection_floor:number; eye_width_ui:number|null; eye_height_dac:number|null; width_clipped?:boolean; height_clipped?:boolean}|null;
}

export interface RoceCapabilities {
  qualifications: { id: string; title: string; date: string; scope: string; conditions: string; limitations: string; report: string;
    metrics: { label: string; value: number; unit: string }[] }[];
  modes: { id: string; label: string; status: string; reason: string }[];
  features: { id: string; label: string; status: string; reason: string }[];
  speeds_gbps: number[]; priorities: number[]; minimum_ports: number;
  cable_length_m: { min: number; max: number; default: number };
  response_time_ns: { min: number; max: number; default: number };
  scope: string; buffer_scope: string;
}
export interface RocePreflight {
  valid: boolean;
  issues: { path: string; message: string; port?: number|null }[];
  warnings?: string[];
  ports: { port: number; epl: number; obt: number; speed_gbps: number; eligible: boolean; reason: string; enabled: boolean; mtu: number; tagged_vlans: number[]; headroom_bytes: number|null; capacity_bytes: number }[];
  suggestions: { path: string; before: unknown; after: unknown; label: string }[];
  common_vlans?: number[];
  budget?: { valid: boolean; lossless_partition_bytes: number; remaining_bytes: number; pause_buffer_bytes: number; cardinal_ports: number };
  affected_epls?: number[];
  dscp_map?: number[];
  dcbx_policy?: { enabled: boolean; bandwidth: number[]; priority_map: number[]; tsa_map: number[]; pfc_mask: number };
}
export interface DcbxOperational {
  mode: string; quality: string; configuration_matches: boolean; peer_policy_applied?: boolean;
  ports: { port: number; configuration_matches: boolean; state: string; tx_frames: number|null;
    local: Record<string,unknown>|null; peers: { state: string; system_name: string; age_seconds: string|null; ttl: string|null; policy: Record<string,unknown>|null }[] }[];
}
export interface RoceOperational {
  revision?: number; sampled_at?: number; server_time?: number; quality: string; enabled?: boolean;
  configuration_applied: boolean; buffer_ready: boolean; buffer_status?: string;
  traffic_validation: string; ecn?: string; dcbx?: DcbxOperational; pause_source_mac?: string;
  classification?: string; dscp_map?: number[]|null;
  cnp_queue?: { enabled: boolean; dscp: number; priority: number; traffic_class: number; pfc: boolean; scheduler: string };
  diagnostics?: { interval_seconds: number; persistent: boolean; automatic_recovery: boolean; observation: string;
    ports: { port: number; pause_observed: boolean|null; observed_stall_seconds: number; suspected_stall: boolean; tc3_peak_bytes: number|null; quality: string }[];
    events: { time: number; revision: number; port: number; kind: string; message: string; automatic_action: boolean }[] };
  tc_smp_map: string[]; smp_usage_bytes?: (number|null)[];
  ports: { port: number; selected: boolean; configuration_matches?: boolean; link: string;
    state_quality?: string; counter_quality?: string; pc3_smp?: number|null;
    quality?: string; tc3_usage_bytes: number|null; rx_smp0_usage_bytes?: number|null; rx_smp1_usage_bytes?: number|null;
    cnp_usage_bytes?: number|null;
    watchdog?: {supported:boolean; enabled:boolean; phase:string; quality:string;
      configuration_matches:boolean; saved_rx_mask:number|null; hardware_rx_mask:number|null;
      detections:number|null; restorations:number|null; failures:number|null; gaps:number|null};
    pause?: { quality: string; rx_quanta: number[]|null; paused_class_mask: number|null; generated_smp_mask: number|null };
    counters: Record<string, number|null> }[];
  shared_watermarks?: Record<string,string>[];
  watermarks?: { port: number; partitions: Record<string,string>[]; traffic_classes: Record<string,string>[] }[];
}
