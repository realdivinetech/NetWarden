import React from "react"
import ReactDOM from "react-dom/client"
import App from "./App"
import { AppProviders } from "./app/providers"
import { ErrorBoundary } from "./components/ErrorBoundary"
import "./styles/globals.css"

window.addEventListener("error", (event) => {
  window.runtime?.EventsEmit?.("frontend:error", event.message)
})
window.addEventListener("unhandledrejection", (event) => {
  const reason = event.reason
  const message = reason instanceof Error ? reason.message : String(reason)
  window.runtime?.EventsEmit?.("frontend:error", `unhandled rejection: ${message}`)
})

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AppProviders>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </AppProviders>
  </React.StrictMode>,
)
