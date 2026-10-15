import { useState } from "react"
import { LoaderCircle, Play } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import type { Device, Preset } from "@/lib/wails/types"
import { useApplyPreset, usePresets } from "./automation.queries"

function describePreset(preset?: Preset) {
  if (!preset) return "Choose a preset to apply to this device."
  switch (preset.action) {
    case "disconnect":
      return "Disconnect this device from the network."
    case "limit": {
      const download = preset.download_bits_per_second ? `${(preset.download_bits_per_second / 1_000_000).toFixed(1)} Mbit/s down` : "no download limit"
      const upload = preset.upload_bits_per_second ? `${(preset.upload_bits_per_second / 1_000_000).toFixed(1)} Mbit/s up` : "no upload limit"
      return `Limit bandwidth to ${download} and ${upload}.`
    }
    case "block":
      return `Block ${preset.domains?.length ?? 0} hostname(s) for this device.`
    default:
      return ""
  }
}

export function PresetApplySection({ device }: { device: Device }) {
  const { data: presets = [] } = usePresets()
  const apply = useApplyPreset()
  const [selectedID, setSelectedID] = useState("")
  const selected = presets.find((preset) => preset.id === selectedID) ?? presets[0]
  const eligible = device.online && device.role === "Device" && device.controlState === ""
  const pending = apply.isPending

  return (
    <section className="space-y-3 py-6">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold">Apply preset</h4>
        <Badge variant={eligible ? "outline" : "secondary"}>
          {pending && <LoaderCircle className="animate-spin" />}
          {eligible ? "Available" : "Unavailable"}
        </Badge>
      </div>
      {presets.length === 0 ? (
        <p className="text-xs text-muted-foreground">No presets configured yet. Add one from the Automation view.</p>
      ) : (
        <>
          <div className="space-y-2">
            <Label htmlFor={`preset-${device.mac}`}>Preset</Label>
            <NativeSelect
              id={`preset-${device.mac}`}
              className="w-full"
              value={selected?.id ?? ""}
              disabled={!eligible || pending}
              onChange={(event) => setSelectedID(event.target.value)}
            >
              {presets.map((preset) => (
                <NativeSelectOption key={preset.id} value={preset.id}>
                  {preset.name}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </div>
          <p className="text-xs text-muted-foreground">{describePreset(selected)}</p>
          <Button
            size="sm"
            disabled={!eligible || pending || !selected}
            onClick={() => selected && apply.mutate({ id: selected.id, ip: device.ip, mac: device.mac })}
          >
            <Play />
            Apply preset
          </Button>
        </>
      )}
    </section>
  )
}
