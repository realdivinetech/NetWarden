import { useEffect, useState } from "react"
import { useQueryClient } from "@tanstack/react-query"
import { AppShell, type AppView } from "@/app/AppShell"
import { DevicesView } from "@/features/devices/DevicesView"
import { IntegrityView } from "@/features/integrity/IntegrityView"
import { SettingsView } from "@/features/settings/SettingsView"
import { DiagnosticsView } from "@/features/diagnostics/DiagnosticsView"
import { useUnsavedChanges } from "@/app/unsaved-changes"
import { BandwidthMonitorView } from "@/features/bandwidth/BandwidthMonitorView"
import { AutomationView } from "@/features/automation/AutomationView"
import { AuthGate } from "@/features/auth/AuthGate"
import { useGatewayStatus } from "@/features/auth/auth.queries"
import { queryKeys } from "@/lib/query-keys"

export default function App() {
  const [view, setView] = useState<AppView>("devices")
  const { dirty } = useUnsavedChanges()
  const queryClient = useQueryClient()
  const { data: gateway } = useGatewayStatus()

  useEffect(() => {
    const unsubscribe = window.runtime?.EventsOn?.("gateway:changed", () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.gateway })
    })
    return () => unsubscribe?.()
  }, [queryClient])

  const changeView = (next: AppView) => {
    if (next === view || !dirty || window.confirm("Discard unsaved settings changes?")) setView(next)
  }

  if (!gateway?.authorized) return <AuthGate />

  return (
    <AppShell view={view} onViewChange={changeView}>
      {view === "devices" && <DevicesView />}
      {view === "bandwidth" && <BandwidthMonitorView />}
      {view === "automation" && (
        <section className="py-7 sm:py-9">
          <AutomationView />
        </section>
      )}
      {view === "integrity" && (
        <section className="py-7 sm:py-9">
          <IntegrityView />
        </section>
      )}
      {view === "diagnostics" && (
        <section className="py-7 sm:py-9">
          <DiagnosticsView />
        </section>
      )}
      {view === "settings" && (
        <section className="py-7 sm:py-9">
          <SettingsView />
        </section>
      )}
    </AppShell>
  )
}
