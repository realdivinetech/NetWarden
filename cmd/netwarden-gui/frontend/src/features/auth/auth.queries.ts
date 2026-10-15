import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { queryKeys } from "@/lib/query-keys"
import { wailsClient } from "@/lib/wails/client"
import { errorMessage } from "@/lib/errors"

export type AuthorizeVariables = { username: string; password: string; acceptUnverified: boolean }

export const useGatewayStatus = () =>
  useQuery({ queryKey: queryKeys.gatewayStatus, queryFn: wailsClient.gatewayStatus })

export function useAuthorizeGateway() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (variables: AuthorizeVariables) =>
      wailsClient.authorizeGateway(variables.username, variables.password, variables.acceptUnverified),
    onSuccess: async (status) => {
      await client.invalidateQueries()
      if (status.verified) {
        toast.success("Router authorized", { description: `Verified through ${strategyLabel(status.strategy)}.` })
      } else {
        toast.success("Session opened without verification", {
          description: "Your router could not confirm the password, so this session carries an unverified badge.",
        })
      }
    },
    onError: (error) => toast.error("Authorization failed", { description: errorMessage(error) }),
  })
}

export function useForgetGateway() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: wailsClient.gatewayForget,
    onSuccess: async () => {
      await client.invalidateQueries()
      toast.success("Router authorization cleared", {
        description: "NetWarden is locked until the router is authorized again.",
      })
    },
    onError: (error) => toast.error("Could not clear authorization", { description: errorMessage(error) }),
  })
}

const strategyNames: Record<string, string> = {
  "http-basic": "HTTP Basic",
  "http-digest": "HTTP Digest",
  "huawei-ont": "Huawei ONT",
  "mikrotik-routeros-api": "MikroTik RouterOS",
  "openwrt-luci": "OpenWrt / LuCI",
  asuswrt: "ASUSWRT",
}

export function strategyLabel(strategy?: string) {
  if (!strategy) return "an unverified adapter"
  return strategyNames[strategy] ?? strategy
}
