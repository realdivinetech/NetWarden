import { useState } from "react"
import { LoaderCircle, Plus, Save, Trash2 } from "lucide-react"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Switch } from "@/components/ui/switch"
import { useDevices } from "@/features/devices/devices.queries"
import type { Preset, PresetAction, Schedule } from "@/lib/wails/types"
import {
  useClearDomainBlocks,
  useDomainBlocks,
  usePresets,
  useSavePresets,
  useSaveSchedules,
  useSchedules,
} from "./automation.queries"

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]

function newID(prefix: string) {
  const random = typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`
  return `${prefix}-${random}`.slice(0, 64)
}

export function AutomationView() {
  return (
    <div className="space-y-6">
      <PresetsCard />
      <SchedulesCard />
      <BlockedDevicesCard />
    </div>
  )
}

function PresetsCard() {
  const { data: presets = [] } = usePresets()
  const save = useSavePresets()
  const [draft, setDraft] = useState<Preset[]>(presets)
  const [domainsText, setDomainsText] = useState<Record<string, string>>({})
  const [rates, setRates] = useState<Record<string, { download: string; upload: string }>>({})
  const [sync, setSync] = useState(JSON.stringify(presets))
  const serverSignature = JSON.stringify(presets)
  if (serverSignature !== sync) {
    setSync(serverSignature)
    setDraft(presets)
    setDomainsText({})
    setRates({})
  }

  const update = (id: string, patch: Partial<Preset>) =>
    setDraft((current) => current.map((preset) => (preset.id === id ? { ...preset, ...patch } : preset)))

  const build = (): Preset[] =>
    draft.map((preset) => {
      const base: Preset = { id: preset.id, name: preset.name.trim(), action: preset.action }
      if (preset.action === "limit") {
        const download = Math.round((Number.parseFloat(rates[preset.id]?.download ?? "") || 0) * 1_000_000)
        const upload = Math.round((Number.parseFloat(rates[preset.id]?.upload ?? "") || 0) * 1_000_000)
        if (download > 0) base.download_bits_per_second = download
        if (upload > 0) base.upload_bits_per_second = upload
      }
      if (preset.action === "block") {
        const text = domainsText[preset.id] ?? (preset.domains ?? []).join(", ")
        base.domains = text
          .split(/[\s,]+/)
          .map((entry) => entry.trim().toLowerCase())
          .filter(Boolean)
      }
      return base
    })

  const rateValue = (preset: Preset, field: "download" | "upload") => {
    const typed = rates[preset.id]?.[field]
    if (typed !== undefined) return typed
    const bits = field === "download" ? preset.download_bits_per_second : preset.upload_bits_per_second
    return bits ? String(bits / 1_000_000) : ""
  }

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-3">
        <div>
          <CardTitle>Presets</CardTitle>
          <CardDescription>Reusable actions applied to a device manually or on a schedule.</CardDescription>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setDraft((current) => [...current, { id: newID("preset"), name: "New preset", action: "disconnect" }])}
        >
          <Plus />
          Add preset
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {draft.length === 0 && <p className="text-xs text-muted-foreground">No presets yet. Add one to reuse actions.</p>}
        {draft.map((preset) => (
          <div key={preset.id} className="space-y-3 rounded-lg border bg-background/30 p-4">
            <div className="flex items-start gap-3">
              <div className="flex-1 space-y-2">
                <Label htmlFor={`preset-name-${preset.id}`}>Name</Label>
                <Input
                  id={`preset-name-${preset.id}`}
                  maxLength={64}
                  value={preset.name}
                  onChange={(event) => update(preset.id, { name: event.target.value })}
                />
              </div>
              <div className="w-40 space-y-2">
                <Label htmlFor={`preset-action-${preset.id}`}>Action</Label>
                <NativeSelect
                  id={`preset-action-${preset.id}`}
                  className="w-full"
                  value={preset.action}
                  onChange={(event) => update(preset.id, { action: event.target.value as PresetAction })}
                >
                  <NativeSelectOption value="disconnect">Disconnect</NativeSelectOption>
                  <NativeSelectOption value="limit">Limit bandwidth</NativeSelectOption>
                  <NativeSelectOption value="block">Block websites</NativeSelectOption>
                </NativeSelect>
              </div>
              <Button
                variant="ghost"
                size="icon"
                className="mt-6"
                aria-label={`Remove ${preset.name}`}
                onClick={() => setDraft((current) => current.filter((entry) => entry.id !== preset.id))}
              >
                <Trash2 />
              </Button>
            </div>
            {preset.action === "limit" && (
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label htmlFor={`preset-download-${preset.id}`}>Download (Mbit/s)</Label>
                  <Input
                    id={`preset-download-${preset.id}`}
                    type="number"
                    min="0"
                    step="0.1"
                    placeholder="Unlimited"
                    value={rateValue(preset, "download")}
                    onChange={(event) =>
                      setRates((current) => ({ ...current, [preset.id]: { ...current[preset.id], download: event.target.value, upload: current[preset.id]?.upload ?? "" } }))
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`preset-upload-${preset.id}`}>Upload (Mbit/s)</Label>
                  <Input
                    id={`preset-upload-${preset.id}`}
                    type="number"
                    min="0"
                    step="0.1"
                    placeholder="Unlimited"
                    value={rateValue(preset, "upload")}
                    onChange={(event) =>
                      setRates((current) => ({ ...current, [preset.id]: { download: current[preset.id]?.download ?? "", upload: event.target.value } }))
                    }
                  />
                </div>
                <p className="col-span-2 text-xs text-muted-foreground">Set at least one direction. 0 leaves that direction unlimited.</p>
              </div>
            )}
            {preset.action === "block" && (
              <div className="space-y-2">
                <Label htmlFor={`preset-domains-${preset.id}`}>Blocked hostnames</Label>
                <Input
                  id={`preset-domains-${preset.id}`}
                  placeholder="ads.example.com, tracker.example.com"
                  value={domainsText[preset.id] ?? (preset.domains ?? []).join(", ")}
                  onChange={(event) => setDomainsText((current) => ({ ...current, [preset.id]: event.target.value }))}
                />
                <p className="text-xs text-muted-foreground">Separate hostnames with commas or spaces.</p>
              </div>
            )}
          </div>
        ))}
        <div className="flex justify-end">
          <Button disabled={save.isPending} onClick={() => save.mutate(build())}>
            {save.isPending ? <LoaderCircle className="animate-spin" /> : <Save />}
            Save presets
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

function SchedulesCard() {
  const { data: schedules = [] } = useSchedules()
  const { data: presets = [] } = usePresets()
  const { data: allDevices = [] } = useDevices()
  const devices = allDevices.filter((device) => device.role === "Device")
  const save = useSaveSchedules()
  const [draft, setDraft] = useState<Schedule[]>(schedules)
  const [sync, setSync] = useState(JSON.stringify(schedules))
  const serverSignature = JSON.stringify(schedules)
  if (serverSignature !== sync) {
    setSync(serverSignature)
    setDraft(schedules)
  }

  const update = (id: string, patch: Partial<Schedule>) =>
    setDraft((current) => current.map((schedule) => (schedule.id === id ? { ...schedule, ...patch } : schedule)))

  const toggleDay = (schedule: Schedule, day: number) =>
    update(schedule.id, {
      days: schedule.days.includes(day) ? schedule.days.filter((value) => value !== day) : [...schedule.days, day].sort((a, b) => a - b),
    })

  const toggleDevice = (schedule: Schedule, mac: string) =>
    update(schedule.id, {
      macs: schedule.macs.includes(mac) ? schedule.macs.filter((value) => value !== mac) : [...schedule.macs, mac],
    })

  const addSchedule = () =>
    setDraft((current) => [
      ...current,
      {
        id: newID("schedule"),
        name: "New schedule",
        enabled: true,
        days: [1, 2, 3, 4, 5],
        start: "22:00",
        end: "06:00",
        preset_id: presets[0]?.id ?? "",
        macs: [],
      },
    ])

  const build = (): Schedule[] =>
    draft.map((schedule) => ({
      id: schedule.id,
      name: schedule.name.trim(),
      enabled: schedule.enabled,
      days: [...schedule.days].sort((a, b) => a - b),
      start: schedule.start,
      end: schedule.end,
      preset_id: schedule.preset_id,
      macs: schedule.macs,
    }))

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-3">
        <div>
          <CardTitle>Schedules</CardTitle>
          <CardDescription>Apply a preset to selected devices during a recurring weekly window.</CardDescription>
        </div>
        <Button variant="outline" size="sm" disabled={presets.length === 0} onClick={addSchedule}>
          <Plus />
          Add schedule
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {presets.length === 0 && <p className="text-xs text-muted-foreground">Create a preset first — schedules apply presets.</p>}
        {draft.length === 0 && presets.length > 0 && (
          <p className="text-xs text-muted-foreground">No schedules yet. Add one to automate device actions.</p>
        )}
        {draft.map((schedule) => (
          <div key={schedule.id} className="space-y-4 rounded-lg border bg-background/30 p-4">
            <div className="flex items-start gap-3">
              <div className="flex-1 space-y-2">
                <Label htmlFor={`schedule-name-${schedule.id}`}>Name</Label>
                <Input
                  id={`schedule-name-${schedule.id}`}
                  maxLength={64}
                  value={schedule.name}
                  onChange={(event) => update(schedule.id, { name: event.target.value })}
                />
              </div>
              <div className="flex items-center gap-2 pt-6">
                <Switch
                  id={`schedule-enabled-${schedule.id}`}
                  checked={schedule.enabled}
                  onCheckedChange={(checked) => update(schedule.id, { enabled: checked })}
                />
                <Label htmlFor={`schedule-enabled-${schedule.id}`}>Enabled</Label>
              </div>
              <Button
                variant="ghost"
                size="icon"
                className="mt-6"
                aria-label={`Remove ${schedule.name}`}
                onClick={() => setDraft((current) => current.filter((entry) => entry.id !== schedule.id))}
              >
                <Trash2 />
              </Button>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-2">
                <Label htmlFor={`schedule-start-${schedule.id}`}>Start</Label>
                <Input
                  id={`schedule-start-${schedule.id}`}
                  type="time"
                  value={schedule.start}
                  onChange={(event) => update(schedule.id, { start: event.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor={`schedule-end-${schedule.id}`}>End</Label>
                <Input
                  id={`schedule-end-${schedule.id}`}
                  type="time"
                  value={schedule.end}
                  onChange={(event) => update(schedule.id, { end: event.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor={`schedule-preset-${schedule.id}`}>Preset</Label>
                <NativeSelect
                  id={`schedule-preset-${schedule.id}`}
                  className="w-full"
                  value={schedule.preset_id}
                  onChange={(event) => update(schedule.id, { preset_id: event.target.value })}
                >
                  <NativeSelectOption value="">Select a preset</NativeSelectOption>
                  {presets.map((preset) => (
                    <NativeSelectOption key={preset.id} value={preset.id}>
                      {preset.name}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              </div>
            </div>
            <div className="space-y-2">
              <Label>Days</Label>
              <div className="flex flex-wrap gap-1">
                {DAYS.map((label, day) => (
                  <Button
                    key={label}
                    type="button"
                    size="sm"
                    variant={schedule.days.includes(day) ? "default" : "outline"}
                    onClick={() => toggleDay(schedule, day)}
                  >
                    {label}
                  </Button>
                ))}
              </div>
            </div>
            <div className="space-y-2">
              <Label>Devices</Label>
              {devices.length === 0 ? (
                <p className="text-xs text-muted-foreground">No devices discovered yet.</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {devices.map((device) => {
                    const selected = schedule.macs.includes(device.mac)
                    return (
                      <Button
                        key={device.mac}
                        type="button"
                        size="sm"
                        variant={selected ? "default" : "outline"}
                        disabled={!device.online && !selected}
                        title={device.online ? undefined : "Device is offline"}
                        onClick={() => toggleDevice(schedule, device.mac)}
                      >
                        {device.name}
                      </Button>
                    )
                  })}
                </div>
              )}
            </div>
          </div>
        ))}
        <div className="flex justify-end">
          <Button disabled={save.isPending} onClick={() => save.mutate(build())}>
            {save.isPending ? <LoaderCircle className="animate-spin" /> : <Save />}
            Save schedules
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

function BlockedDevicesCard() {
  const { data: blocks = [] } = useDomainBlocks()
  const clear = useClearDomainBlocks()
  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-3">
        <div>
          <CardTitle>Blocked devices</CardTitle>
          <CardDescription>Per-device deny lists currently saved or enforced across the network.</CardDescription>
        </div>
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button variant="outline" size="sm" disabled={blocks.length === 0 || clear.isPending}>
              {clear.isPending ? <LoaderCircle className="animate-spin" /> : <Trash2 />}
              Clear all
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Clear every block list?</AlertDialogTitle>
              <AlertDialogDescription>This removes saved and enforced hostname blocks for all devices.</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction onClick={() => clear.mutate()}>Clear all</AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </CardHeader>
      <CardContent className="space-y-2">
        {blocks.length === 0 && <p className="text-xs text-muted-foreground">No devices have blocked hostnames.</p>}
        {blocks.map((block) => (
          <div key={block.mac} className="rounded-lg border bg-background/30 p-3">
            <div className="flex items-center justify-between gap-3">
              <span className="text-xs font-medium">{block.ip || block.mac}</span>
              <Badge variant={block.active ? "destructive" : "secondary"}>{block.active ? "Enforced" : "Saved"}</Badge>
            </div>
            <p className="mt-1 font-mono text-[10px] text-muted-foreground">{block.mac}</p>
            <p className="mt-2 text-xs text-muted-foreground">{(block.domains ?? []).join(", ")}</p>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
