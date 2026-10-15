import { useState, type FormEvent } from "react"
import { KeyRound, Loader2, Router, ShieldQuestion } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { BrandIcon } from "@/app/AppShell"
import { errorMessage, isBackendUnavailable } from "@/lib/errors"
import { useAuthorizeGateway, useGatewayStatus } from "./auth.queries"

export function AuthGate() {
  const status = useGatewayStatus()
  const authorize = useAuthorizeGateway()
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [continueUnverified, setContinueUnverified] = useState(false)

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (!password || authorize.isPending) return
    authorize.mutate({ username, password, acceptUnverified: continueUnverified })
  }

  if (status.isPending) {
    return (
      <main className="mx-auto flex min-h-screen max-w-xl flex-col justify-center gap-6 px-4 py-10">
        <GateHeader />
        <Card className="bg-card/60">
          <CardContent className="space-y-4 py-8">
            <Skeleton className="h-5 w-2/3" />
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-32" />
          </CardContent>
        </Card>
      </main>
    )
  }

  if (status.isError) {
    return (
      <main className="mx-auto flex min-h-screen max-w-xl flex-col justify-center gap-6 px-4 py-10">
        <GateHeader />
        <Alert variant="destructive">
          <AlertTitle>{isBackendUnavailable(status.error) ? "Backend unavailable" : "Gateway unknown"}</AlertTitle>
          <AlertDescription>{errorMessage(status.error)}</AlertDescription>
        </Alert>
      </main>
    )
  }

  const gateway = status.data

  return (
    <main className="mx-auto flex min-h-screen max-w-xl flex-col justify-center gap-6 px-4 py-10">
      <GateHeader />

      <Card className="bg-card/60 shadow-[0_0_48px_color-mix(in_oklch,var(--primary),transparent_12%)]">
        <CardHeader className="border-b">
          <div className="flex items-start justify-between gap-4">
            <div className="space-y-1.5">
              <CardTitle>Authorize this router</CardTitle>
              <CardDescription>
                NetWarden proves you control this network&apos;s gateway before it touches the network. Sign in with the
                router&apos;s administrator password.
              </CardDescription>
            </div>
            <Badge variant="outline" className="shrink-0 gap-1.5 rounded-full px-3 py-1.5 text-muted-foreground">
              <Router className="size-3" />
              {gateway?.gatewayIP || "gateway unknown"}
            </Badge>
          </div>
        </CardHeader>

        <CardContent className="space-y-5 py-7">
          {gateway?.error ? (
            <Alert variant="destructive">
              <AlertTitle>Network check failed</AlertTitle>
              <AlertDescription>{gateway.error}</AlertDescription>
            </Alert>
          ) : null}

          {authorize.isError ? (
            <Alert variant="destructive">
              <AlertTitle>Authorization failed</AlertTitle>
              <AlertDescription>{errorMessage(authorize.error)}</AlertDescription>
            </Alert>
          ) : null}

          <form onSubmit={submit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="gateway-username">Router username</Label>
              <Input
                id="gateway-username"
                autoComplete="username"
                placeholder="admin"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Leave blank when your router only asks for a password.
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="gateway-password">Router password</Label>
              <Input
                id="gateway-password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </div>

            <div className="flex items-start gap-3 rounded-lg border border-border/70 bg-muted/30 p-3">
              <input
                id="gateway-unverified"
                type="checkbox"
                checked={continueUnverified}
                onChange={(event) => setContinueUnverified(event.target.checked)}
                className="mt-0.5 size-4 shrink-0 accent-[var(--primary)]"
              />
              <div className="space-y-1">
                <Label htmlFor="gateway-unverified" className="cursor-pointer">
                  Continue without verification
                </Label>
                <p className="text-xs text-muted-foreground">
                  If no adapter recognizes this router — or the router refuses a password you are sure is right — open
                  an unverified session instead. NetWarden cannot confirm the password in that case.
                </p>
              </div>
            </div>

            <Button type="submit" className="w-full" disabled={authorize.isPending || !password}>
              {authorize.isPending ? (
                <>
                  <Loader2 className="animate-spin" />
                  Checking with the router…
                </>
              ) : (
                <>
                  <KeyRound />
                  Authorize
                </>
              )}
            </Button>
          </form>

          <p className="flex items-start gap-2 text-xs text-muted-foreground">
            <ShieldQuestion className="mt-0.5 size-3.5 shrink-0" />
            The password travels only to your router and is never stored. NetWarden keeps a sealed proof of this session
            instead, bound to this gateway&apos;s address.
          </p>
        </CardContent>
      </Card>

      <p className="text-center text-[10px] text-muted-foreground">
        NetWarden runs locally. Network data stays on this device.
      </p>
    </main>
  )
}

function GateHeader() {
  return (
    <header className="flex items-center gap-3">
      <BrandIcon />
      <div>
        <h1 className="text-sm font-semibold">NetWarden</h1>
        <p className="text-[10px] text-muted-foreground">Router authorization required</p>
      </div>
    </header>
  )
}
