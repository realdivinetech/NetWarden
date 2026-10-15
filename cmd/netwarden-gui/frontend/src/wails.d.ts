export {}
declare global {
  interface Window {
    go?: { main?: { GUIApp?: Record<string, (...args: any[]) => Promise<any>> } }
    runtime?: {
      EventsOn: (name: string, callback: (...args: any[]) => void) => () => void
      EventsEmit?: (name: string, data?: unknown) => void
      ClipboardSetText?: (text: string) => Promise<boolean>
    }
  }
}
