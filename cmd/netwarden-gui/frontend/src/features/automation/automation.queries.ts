import { useMutation, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { announce } from "@/lib/accessibility"
import { errorMessage } from "@/lib/errors"
import { queryKeys } from "@/lib/query-keys"
import { wailsClient } from "@/lib/wails/client"
import type { Preset, Schedule } from "@/lib/wails/types"

const blockKeys = [queryKeys.domainBlocks, queryKeys.status, queryKeys.devices] as const

async function invalidate(client: QueryClient, keys: readonly (readonly unknown[])[]) {
  await Promise.all(keys.map((key) => client.invalidateQueries({ queryKey: key })))
}

export const useDomainBlocks = () =>
  useQuery({ queryKey: queryKeys.domainBlocks, queryFn: wailsClient.domainBlocks, refetchInterval: 5_000 })

export function useSetDomainBlock() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ ip, mac, domains }: { ip: string; mac: string; domains: string[] }) =>
      wailsClient.setDomainBlock(ip, mac, domains),
    onSuccess: async () => {
      await invalidate(client, blockKeys)
      toast.success("Block list saved")
      announce("Block list saved")
    },
    onError: (error) => {
      const message = errorMessage(error)
      toast.error("Could not save block list", { description: message })
      announce(`Could not save block list. ${message}`, "assertive")
    },
  })
}

export function useRemoveDomainBlock() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (mac: string) => wailsClient.removeDomainBlock(mac),
    onSuccess: async () => {
      await invalidate(client, blockKeys)
      toast.success("Block list removed")
      announce("Block list removed")
    },
    onError: (error) => {
      const message = errorMessage(error)
      toast.error("Could not remove block list", { description: message })
      announce(`Could not remove block list. ${message}`, "assertive")
    },
  })
}

export function useClearDomainBlocks() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: () => wailsClient.clearDomainBlocks(),
    onSuccess: async () => {
      await invalidate(client, blockKeys)
      toast.success("All block lists removed")
      announce("All block lists removed")
    },
    onError: (error) => {
      const message = errorMessage(error)
      toast.error("Could not clear block lists", { description: message })
      announce(`Could not clear block lists. ${message}`, "assertive")
    },
  })
}

export const usePresets = () => useQuery({ queryKey: queryKeys.presets, queryFn: wailsClient.presets })

export function useSavePresets() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (presets: Preset[]) => wailsClient.savePresets(presets),
    onSuccess: async (saved) => {
      await Promise.all([
        client.invalidateQueries({ queryKey: queryKeys.presets }),
        client.invalidateQueries({ queryKey: queryKeys.schedules }),
      ])
      toast.success("Presets saved")
      announce("Presets saved")
      return saved
    },
    onError: (error) => {
      const message = errorMessage(error)
      toast.error("Could not save presets", { description: message })
      announce(`Could not save presets. ${message}`, "assertive")
    },
  })
}

export function useApplyPreset() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ip, mac }: { id: string; ip: string; mac: string }) => wailsClient.applyPreset(id, ip, mac),
    onSuccess: async () => {
      await invalidate(client, [queryKeys.status, queryKeys.devices, queryKeys.domainBlocks, queryKeys.controlAudit])
      toast.success("Preset applied")
      announce("Preset applied")
    },
    onError: (error) => {
      const message = errorMessage(error)
      toast.error("Could not apply preset", { description: message })
      announce(`Could not apply preset. ${message}`, "assertive")
    },
  })
}

export const useSchedules = () => useQuery({ queryKey: queryKeys.schedules, queryFn: wailsClient.schedules })

export function useSaveSchedules() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (schedules: Schedule[]) => wailsClient.saveSchedules(schedules),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: queryKeys.schedules })
      toast.success("Schedules saved")
      announce("Schedules saved")
    },
    onError: (error) => {
      const message = errorMessage(error)
      toast.error("Could not save schedules", { description: message })
      announce(`Could not save schedules. ${message}`, "assertive")
    },
  })
}
