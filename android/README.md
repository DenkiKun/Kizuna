# Android (Kotlin)

Projeto Android a criar com o Android Studio (módulo `app`, Kotlin, minSdk 29).

## Componentes do MVP

- `NotificationListenerService`: captura notificações e envia `notification.posted`
- Serviço em primeiro plano: mantém a ligação ao PC, sempre com notificação visível
- Cliente de rede: mDNS (`NsdManager`) + TLS
- Leitor de QR para o emparelhamento

## Notas

- Todas as permissões sensíveis (acesso a notificações, localização) são pedidas de forma explícita.
- Sem funções ocultas: o utilizador vê sempre quando algo está ativo.
