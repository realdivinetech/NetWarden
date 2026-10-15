import { useState } from "react"
import { Ban, LoaderCircle, Plus, ShieldOff, X } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import type { Device, DomainBlock } from "@/lib/wails/types"
import { useRemoveDomainBlock, useSetDomainBlock } from "./automation.queries"

function isBlockEligible(device: Device) {
  return device.online && device.role === "Device" && device.controlState === ""
}

function domainError(value: string) {
  if (value.length > 253 || value.startsWith(".") || value.endsWith(".")) return "Enter a hostname such as example.com"
  if (!/^[a-z0-9][a-z0-9._-]*$/i.test(value)) return "Hostnames may only contain letters, numbers, dots, dashes, and underscores"
  return ""
}

export function DomainBlockSection({
  device,
  block,
  available,
}: {
  device: Device
  block?: DomainBlock
  available: boolean
}) {
  const [domains, setDomains] = useState<string[]>(block?.domains ?? [])
  const [draft, setDraft] = useState("")
  const [inputError, setInputError] = useState("")
  const setBlock = useSetDomainBlock()
  const removeBlock = useRemoveDomainBlock()
  const signature = `${device.mac}:${(block?.domains ?? []).join("|")}`
  const [lastSignature, setLastSignature] = useState(signature)
  if (signature !== lastSignature) {
    setLastSignature(signature)
    setDomains(block?.domains ?? [])
    setDraft("")
    setInputError("")
  }
  const eligible = available && isBlockEligible(device)
  const pending = setBlock.isPending || removeBlock.isPending
  const saved = block?.domains ?? []
  const dirty = domains.length !== saved.length || domains.some((domain, index) => domain !== saved[index])

  const addDomain = () => {
    const value = draft.trim().toLowerCase()
    const error = value ? domainError(value) : ""
    if (error) {
      setInputError(error)
      return
    }
    if (!value || domains.includes(value)) {
      setDraft("")
      setInputError("")
      return
    }
    setDomains((current) => [...current, value])
    setDraft("")
    setInputError("")
  }
  const description = !available
    ? "Domain blocking is unavailable with the active capture backend."
    : device.role !== "Device"
      ? "This protected network endpoint cannot be blocked."
      : device.controlState !== ""
        ? "Restore normal access before editing this device's block list."
        : !device.online
          ? "The device must be online before changing its block list."
          : "Blocked hostnames are matched against DNS and TLS SNI traffic for this device."

  return (
    <section className="space-y-3 py-6">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold">Website blocking</h4>
        <Badge variant={block?.active ? "destructive" : block ? "outline" : eligible ? "outline" : "secondary"}>
          {pending && <LoaderCircle className="animate-spin" />}
          {block?.active ? "Enforced" : block ? "Saved" : eligible ? "Available" : "Unavailable"}
        </Badge>
      </div>
      {domains.length > 0 ? (
        <ul className="space-y-1">
          {domains.map((domain) => (
            <li
              key={domain}
              className="flex items-center justify-between gap-3 rounded-md border bg-background/30 px-3 py-1.5"
            >
              <span className="truncate font-mono text-xs" title={domain}>
                {domain}
              </span>
              <Button
                variant="ghost"
                size="icon-xs"
                aria-label={`Remove ${domain}`}
                disabled={!eligible || pending}
                onClick={() => setDomains((current) => current.filter((entry) => entry !== domain))}
              >
                <X />
              </Button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-muted-foreground">No hostnames blocked for this device.</p>
      )}
      <div className="space-y-2">
        <Label htmlFor={`domain-block-${device.mac}`}>Add a hostname</Label>
        <div className="flex gap-2">
          <Input
            id={`domain-block-${device.mac}`}
            placeholder="ads.example.com"
            value={draft}
            disabled={!eligible || pending}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault()
                addDomain()
              }
            }}
          />
          <Button variant="outline" size="icon" aria-label="Add hostname" disabled={!eligible || pending || !draft.trim()} onClick={addDomain}>
            <Plus />
          </Button>
        </div>
      </div>
      <p className={`text-xs ${inputError ? "text-destructive" : "text-muted-foreground"}`}>
        {inputError || (!eligible ? description : "Entries are matched exactly; subdomains must be added separately.")}
      </p>
      <div className="flex flex-wrap gap-2">
        <Button
          size="sm"
          disabled={!eligible || pending || !dirty}
          onClick={() => setBlock.mutate({ ip: device.ip, mac: device.mac, domains })}
        >
          <Ban />
          {block ? "Update block list" : "Block websites"}
        </Button>
        {block && (
          <Button
            variant="outline"
            size="sm"
            disabled={!eligible || pending}
            onClick={() => {
              setDomains([])
              removeBlock.mutate(device.mac)
            }}
          >
            <ShieldOff />
            Remove
          </Button>
        )}
      </div>
    </section>
  )
}
