import { beforeEach, describe, expect, it, vi } from "vitest"
import { wailsClient } from "./client"

describe("wailsClient", () => {
  const backend = {
    Bootstrap: vi.fn(),
    Status: vi.fn(),
    Devices: vi.fn(),
    Conflicts: vi.fn(),
    StartMonitoring: vi.fn(),
    StopMonitoring: vi.fn(),
    ScanNow: vi.fn(),
    SetPeriodicScanEnabled: vi.fn(),
    SetNickname: vi.fn(),
    SetGatewayMAC: vi.fn(),
    ControlAudit: vi.fn(),
    DisconnectAllDevices: vi.fn(),
    DisconnectSelectedDevices: vi.fn(),
    BandwidthLimits: vi.fn(),
    SetBandwidthLimit: vi.fn(),
    RemoveBandwidthLimit: vi.fn(),
    ClearBandwidthLimits: vi.fn(),
    DomainBlocks: vi.fn(),
    SetDomainBlock: vi.fn(),
    RemoveDomainBlock: vi.fn(),
    ClearDomainBlocks: vi.fn(),
    Presets: vi.fn(),
    SavePresets: vi.fn(),
    ApplyPreset: vi.fn(),
    Schedules: vi.fn(),
    SaveSchedules: vi.fn(),
    GatewayStatus: vi.fn(),
    AuthorizeGateway: vi.fn(),
    GatewayForget: vi.fn(),
  }

  beforeEach(() => {
    vi.clearAllMocks()
    window.go = { main: { GUIApp: backend } }
  })

  it("passes selected disconnect targets to the backend", async () => {
    const targets = [{ ip: "192.168.1.20", mac: "00:11:22:33:44:55" }]
    backend.DisconnectSelectedDevices.mockResolvedValue(undefined)
    await wailsClient.disconnectSelectedDevices(targets)
    expect(backend.DisconnectSelectedDevices).toHaveBeenCalledWith(targets)
  })

  it("keeps Wails method names out of feature components", async () => {
    backend.StartMonitoring.mockResolvedValue(undefined)
    await wailsClient.startMonitoring("en0")
    expect(backend.StartMonitoring).toHaveBeenCalledWith("en0")
  })

  it("returns the canonical gateway address from the backend", async () => {
    backend.SetGatewayMAC.mockResolvedValue("00:11:22:33:44:55")
    await expect(wailsClient.setGatewayMAC("00-11-22-33-44-55")).resolves.toBe("00:11:22:33:44:55")
  })

  it("dispatches bulk disconnect to the backend", async () => {
    backend.DisconnectAllDevices.mockResolvedValue(undefined)
    await wailsClient.disconnectAllDevices()
    expect(backend.DisconnectAllDevices).toHaveBeenCalledOnce()
  })

  it("bounds control audit requests by default", async () => {
    backend.ControlAudit.mockResolvedValue([])
    await wailsClient.controlAudit()
    expect(backend.ControlAudit).toHaveBeenCalledWith(250)
  })

  it("passes bandwidth rates with the default burst setting", async () => {
    backend.SetBandwidthLimit.mockResolvedValue(undefined)
    await wailsClient.setBandwidthLimit("192.168.1.20", "00:11:22:33:44:55", 10_000_000, 2_000_000)
    expect(backend.SetBandwidthLimit).toHaveBeenCalledWith(
      "192.168.1.20",
      "00:11:22:33:44:55",
      10_000_000,
      2_000_000,
      0,
    )
  })

  it("passes a device deny list to the backend", async () => {
    backend.SetDomainBlock.mockResolvedValue(undefined)
    await wailsClient.setDomainBlock("192.168.1.20", "00:11:22:33:44:55", ["ads.example.com"])
    expect(backend.SetDomainBlock).toHaveBeenCalledWith("192.168.1.20", "00:11:22:33:44:55", ["ads.example.com"])
  })

  it("dispatches a preset application to the backend", async () => {
    backend.ApplyPreset.mockResolvedValue(undefined)
    await wailsClient.applyPreset("preset-1", "192.168.1.20", "00:11:22:33:44:55")
    expect(backend.ApplyPreset).toHaveBeenCalledWith("preset-1", "192.168.1.20", "00:11:22:33:44:55")
  })

  it("sends the preset list to the backend and returns the normalized result", async () => {
    const presets = [{ id: "p1", name: "Focus", action: "block" as const, domains: ["ads.example.com"] }]
    backend.SavePresets.mockResolvedValue(presets)
    await expect(wailsClient.savePresets(presets)).resolves.toEqual(presets)
    expect(backend.SavePresets).toHaveBeenCalledWith(presets)
  })

  it("sends the schedule list to the backend", async () => {
    const schedules = [
      { id: "s1", name: "Bedtime", enabled: true, days: [1], start: "22:00", end: "06:00", preset_id: "p1", macs: ["00:11:22:33:44:55"] },
    ]
    backend.SaveSchedules.mockResolvedValue(schedules)
    await expect(wailsClient.saveSchedules(schedules)).resolves.toEqual(schedules)
    expect(backend.SaveSchedules).toHaveBeenCalledWith(schedules)
  })

  it("submits gateway credentials with the unverified opt-in", async () => {
    const status = { authorized: true, verified: false, gatewayIP: "192.168.100.1", gatewayMAC: "", usernameRequired: true, adapters: [] }
    backend.AuthorizeGateway.mockResolvedValue(status)
    await expect(wailsClient.authorizeGateway("admin", "hunter2", true)).resolves.toEqual(status)
    expect(backend.AuthorizeGateway).toHaveBeenCalledWith("admin", "hunter2", true)
  })

  it("reads and clears gateway authorization through the backend", async () => {
    const locked = { authorized: false, verified: false, gatewayIP: "", gatewayMAC: "", usernameRequired: false, adapters: ["http-basic"] }
    backend.GatewayStatus.mockResolvedValue(locked)
    await expect(wailsClient.gatewayStatus()).resolves.toEqual(locked)
    backend.GatewayForget.mockResolvedValue(locked)
    await expect(wailsClient.gatewayForget()).resolves.toEqual(locked)
    expect(backend.GatewayForget).toHaveBeenCalledOnce()
  })
})
