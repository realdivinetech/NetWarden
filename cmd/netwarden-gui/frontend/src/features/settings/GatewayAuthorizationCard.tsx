import { ShieldCheck, ShieldOff, ShieldQuestion } from "lucide-react"
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
import { formatDate } from "@/lib/format"
import { cn } from "@/lib/utils"
import { strategyLabel, useForgetGateway, useGatewayStatus } from "@/features/auth/auth.queries"

export function GatewayAuthorizationCard() {
  const { data } = useGatewayStatus()
  const forget = useForgetGateway()
  const authorized = Boolean(data?.authorized)
  const verified = Boolean(data?.verified)

  return (
    <Card className="bg-card/60">
      <CardHeader className="border-b">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle>Router authorization</CardTitle>
            <CardDescription>Who may operate NetWarden on this network</CardDescription>
          </div>
          <Badge
            variant={authorized ? (verified ? "default" : "secondary") : "outline"}
            className={cn("gap-1.5 rounded-full px-3 py-1.5", !authorized && "text-muted-foreground")}
          >
            {authorized ? (
              verified ? (
                <>
                  <ShieldCheck className="size-3" />
                  Verified
                </>
              ) : (
                <>
                  <ShieldQuestion className="size-3" />
                  Unverified
                </>
              )
            ) : (
              <>
                <ShieldOff className="size-3" />
                Locked
              </>
            )}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="grid gap-6 py-6 md:grid-cols-3 md:gap-12">
        <section className="space-y-1.5">
          <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Session</h3>
          <p className="text-sm">
            {authorized ? (
              <>
                Authorized through <span className="font-medium">{strategyLabel(data?.strategy)}</span>
              </>
            ) : (
              "The gateway has not been authorized on this network."
            )}
          </p>
          {data?.authorizedAt && authorized ? (
            <p className="text-xs text-muted-foreground">Recorded {formatDate(data.authorizedAt)}</p>
          ) : null}
        </section>

        <section className="space-y-1.5">
          <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Gateway</h3>
          <p className="text-sm">{data?.gatewayIP || "Not discovered"}</p>
          <p className="text-xs text-muted-foreground">
            {data?.gatewayMAC ? `Hardware address ${data.gatewayMAC}` : "Hardware address not pinned"}
          </p>
        </section>

        <section className="space-y-3">
          <div className="space-y-1.5">
            <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Supported adapters</h3>
            <div className="flex flex-wrap gap-1.5">
              {(data?.adapters ?? []).map((adapter) => (
                <Badge key={adapter} variant="outline" className="font-mono text-[10px]">
                  {adapter}
                </Badge>
              ))}
            </div>
          </div>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="outline" size="sm" disabled={!authorized || forget.isPending}>
                Forget authorization
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Lock NetWarden now?</AlertDialogTitle>
                <AlertDialogDescription>
                  The stored proof is deleted and monitoring stops. NetWarden stays locked until the router is
                  authorized again.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={() => forget.mutate()}>Forget and lock</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </section>
      </CardContent>
    </Card>
  )
}
