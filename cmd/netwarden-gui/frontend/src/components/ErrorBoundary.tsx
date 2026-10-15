import { Component, type ErrorInfo, type ReactNode } from "react"

type ErrorBoundaryProps = { children: ReactNode }
type ErrorBoundaryState = { error: Error | null }

/** Catches render crashes so the window shows a recoverable error card
 * instead of a blank white screen, and reports the error to the backend log. */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    const detail = [error.message, info.componentStack?.trim()].filter(Boolean).join(" | ")
    window.runtime?.EventsEmit?.("frontend:error", detail)
  }

  render() {
    if (!this.state.error) return this.props.children
    return (
      <div className="flex min-h-screen items-center justify-center bg-background p-6">
        <div className="w-full max-w-lg space-y-4 rounded-xl border border-destructive/40 bg-card p-6 text-left">
          <h1 className="text-sm font-semibold text-destructive">Something went wrong</h1>
          <p className="text-xs text-muted-foreground">
            NetWarden hit an unexpected error and stopped rendering this screen. The details were written to the
            activity log.
          </p>
          <pre className="max-h-48 overflow-auto rounded-md bg-background/60 p-3 font-mono text-[11px] leading-relaxed text-muted-foreground">
            {this.state.error.message}
          </pre>
          <div className="flex gap-2">
            <button
              className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90"
              onClick={() => window.location.reload()}
            >
              Reload NetWarden
            </button>
            <button
              className="rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-accent"
              onClick={() => this.setState({ error: null })}
            >
              Try again
            </button>
          </div>
        </div>
      </div>
    )
  }
}
