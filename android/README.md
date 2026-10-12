# Android (Kotlin)

Android project, to be created with Android Studio (`app` module, Kotlin, minSdk 29).

## MVP components

- `NotificationListenerService`: captures notifications and sends `notification.posted`
- Foreground service: keeps the connection to the PC, always with a visible notification
- Network client: mDNS (`NsdManager`) + TLS
- QR scanner for pairing

## Notes

- All sensitive permissions (notification access, location) are requested explicitly.
- No hidden features: the user always sees when something is active.
