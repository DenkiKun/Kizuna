# Android (Kotlin)

The Kizuna app for Android (`app` module, Kotlin, minSdk 29). It has no
third-party runtime dependencies: only the Android SDK.

## Current state

- Device identity: ECDSA P-256 key in the Android Keystore (it never leaves the
  phone), with the self-signed certificate the Keystore creates for it
- Discovery of PCs over mDNS (`NsdManager`, `_kizuna._tcp`) and over UDP
  broadcast, which also works on phone hotspots (they block multicast)
- Connecting by address, as a last resort
- TLS 1.3 connection with the phone's certificate
- Pairing as the initiator: the phone shows the 6-digit code, which is typed on
  the PC (see [docs/PROTOCOL.md](../docs/PROTOCOL.md))

## Building

Requires JDK 17 or newer (Android Studio's bundled JDK works) and the Android
SDK (platform 36).

```sh
./gradlew :app:testDebugUnitTest   # JVM unit tests
./gradlew :app:assembleDebug       # app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Next MVP components

- `NotificationListenerService`: captures notifications and sends `notification.posted`
- Foreground service: keeps the connection to the PC, always with a visible notification
- QR scanner for pairing

## Notes

- All sensitive permissions (notification access, location) are requested explicitly.
- No hidden features: the user always sees when something is active.
