import type {
  Activity,
  AppInfo,
  Bootstrap,
  BandwidthLimit,
  BandwidthTraffic,
  BandwidthMonitor,
  BandwidthMeasurement,
  BandwidthBucket,
  BandwidthHealth,
  Conflict,
  ControlAudit,
  Device,
  DomainBlock,
  GatewayStatus,
  HistorySummary,
	IPv6Network,
  MonitoringSettings,
  NotificationSettings,
  Preset,
  RuntimeStatus,
  Schedule,
} from "./types"

const backend = () => {
  const app = window.go?.main?.GUIApp
  if (!app) throw new Error("Wails backend is unavailable in this browser session.")
  return app
}

// A Go nil slice marshals to JSON `null`, and React Query's `data = []`
// destructuring default only applies to `undefined`, not `null`. Without this
// guard a `null` array reaches the UI and `null.length` crashes the screen.
const asArray = async <T>(promise: Promise<T[]>): Promise<T[]> => (await promise) ?? []

export const wailsClient = {
  appInfo: () => backend().AppInfo() as Promise<AppInfo>,
  bootstrap: () => backend().Bootstrap() as Promise<Bootstrap>,
  status: () => backend().Status() as Promise<RuntimeStatus>,
  ipv6Network: () => backend().IPv6Network() as Promise<IPv6Network>,
  devices: () => asArray(backend().Devices() as Promise<Device[]>),
  conflicts: () => asArray(backend().Conflicts() as Promise<Conflict[]>),
  startMonitoring: (interfaceName: string) => backend().StartMonitoring(interfaceName) as Promise<void>,
  stopMonitoring: () => backend().StopMonitoring() as Promise<void>,
  scanNow: () => backend().ScanNow() as Promise<void>,
  setPeriodicScanEnabled: (enabled: boolean) => backend().SetPeriodicScanEnabled(enabled) as Promise<void>,
  setNickname: (mac: string, nickname: string) => backend().SetNickname(mac, nickname) as Promise<void>,
  setGatewayMAC: (mac: string) => backend().SetGatewayMAC(mac) as Promise<string>,
  historySummary: () => backend().HistorySummary() as Promise<HistorySummary>,
  pruneHistory: (olderThanDays: number) => backend().PruneHistory(olderThanDays) as Promise<void>,
  clearHistory: () => backend().ClearHistory() as Promise<void>,
  activity: () => asArray(backend().Activity() as Promise<Activity[]>),
  monitoringSettings: () => backend().MonitoringSettings() as Promise<MonitoringSettings>,
  setMonitoringSettings: (settings: MonitoringSettings) => backend().SetMonitoringSettings(settings) as Promise<void>,
  notificationSettings: () => backend().NotificationSettings() as Promise<NotificationSettings>,
  setNotificationSettings: (settings: NotificationSettings) =>
    backend().SetNotificationSettings(settings) as Promise<void>,
  controlAudit: (limit = 250) => asArray(backend().ControlAudit(limit) as Promise<ControlAudit[]>),
  disconnectDevice: (ip: string, mac: string) => backend().DisconnectDevice(ip, mac) as Promise<void>,
  disconnectAllDevices: () => backend().DisconnectAllDevices() as Promise<void>,
  disconnectSelectedDevices: (targets: Array<{ ip: string; mac: string }>) =>
    backend().DisconnectSelectedDevices(targets) as Promise<void>,
  startContinuousControl: (ip: string, mac: string) => backend().StartContinuousControl(ip, mac) as Promise<void>,
  restoreControl: (ip: string, mac: string) => backend().RestoreControl(ip, mac) as Promise<void>,
  restoreAllControls: () => backend().RestoreAllControls() as Promise<void>,
  stopContinuousControl: (ip: string, mac: string) => backend().StopContinuousControl(ip, mac) as Promise<void>,
  bandwidthLimits: () => asArray(backend().BandwidthLimits() as Promise<BandwidthLimit[]>),
  setBandwidthLimit: (ip: string, mac: string, downloadBitsPerSecond: number, uploadBitsPerSecond: number) =>
    backend().SetBandwidthLimit(ip, mac, downloadBitsPerSecond, uploadBitsPerSecond, 0) as Promise<void>,
  removeBandwidthLimit: (mac: string) => backend().RemoveBandwidthLimit(mac) as Promise<void>,
  clearBandwidthLimits: () => backend().ClearBandwidthLimits() as Promise<void>,
  startBandwidthMonitor: (ip: string, mac: string) => backend().StartBandwidthMonitor(ip, mac) as Promise<void>,
  stopBandwidthMonitor: (mac: string) => backend().StopBandwidthMonitor(mac) as Promise<void>,
  bandwidthTraffic: () => asArray(backend().BandwidthTraffic() as Promise<BandwidthTraffic[]>),
  bandwidthMonitors: () => asArray(backend().BandwidthMonitors() as Promise<BandwidthMonitor[]>),
  bandwidthMeasurements: () => asArray(backend().BandwidthMeasurements() as Promise<BandwidthMeasurement[]>),
  bandwidthHistory: (mac: string, range: string) =>
    asArray(backend().BandwidthHistory(mac, range) as Promise<BandwidthBucket[]>),
  bandwidthMonitorHealth: () => backend().BandwidthMonitorHealth() as Promise<BandwidthHealth>,
  startAllBandwidthMonitors: () => backend().StartAllBandwidthMonitors() as Promise<void>,
  stopAllBandwidthMonitors: () => backend().StopAllBandwidthMonitors() as Promise<void>,
  openConfigurationDirectory: () => backend().OpenConfigurationDirectory() as Promise<void>,
  openLogDirectory: () => backend().OpenLogDirectory() as Promise<void>,
  domainBlocks: () => asArray(backend().DomainBlocks() as Promise<DomainBlock[]>),
  setDomainBlock: (ip: string, mac: string, domains: string[]) =>
    backend().SetDomainBlock(ip, mac, domains) as Promise<void>,
  removeDomainBlock: (mac: string) => backend().RemoveDomainBlock(mac) as Promise<void>,
  clearDomainBlocks: () => backend().ClearDomainBlocks() as Promise<void>,
  presets: () => asArray(backend().Presets() as Promise<Preset[]>),
  savePresets: (presets: Preset[]) => asArray(backend().SavePresets(presets) as Promise<Preset[]>),
  applyPreset: (id: string, ip: string, mac: string) => backend().ApplyPreset(id, ip, mac) as Promise<void>,
  schedules: () => asArray(backend().Schedules() as Promise<Schedule[]>),
  saveSchedules: (schedules: Schedule[]) => asArray(backend().SaveSchedules(schedules) as Promise<Schedule[]>),
  gatewayStatus: () => backend().GatewayStatus() as Promise<GatewayStatus>,
  authorizeGateway: (username: string, password: string, acceptUnverified: boolean) =>
    backend().AuthorizeGateway(username, password, acceptUnverified) as Promise<GatewayStatus>,
  gatewayForget: () => backend().GatewayForget() as Promise<GatewayStatus>,
}
