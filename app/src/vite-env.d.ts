/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_STORE?: string; // "1" in App Store / Play builds
  readonly VITE_API_ORIGIN?: string; // native builds: e.g. https://testnet.kaspachat.com
  readonly VITE_API_AUTH?: string; // private testnet builds only, base64 user:pass, injected at build time
  readonly VITE_API_ONION?: string; // native builds: the services' .onion host, reached through the app's Tor
}

declare const __APP_VERSION__: string; // app/package.json version, set in vite.config.ts
