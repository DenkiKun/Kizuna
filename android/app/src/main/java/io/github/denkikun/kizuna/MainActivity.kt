package io.github.denkikun.kizuna

import android.Manifest
import android.app.Activity
import android.app.Dialog
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.util.Log
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import java.net.InetAddress
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val worker = Executors.newSingleThreadExecutor()
    private lateinit var trusted: TrustedPcs
    private lateinit var discovery: Discovery
    private lateinit var statusIcon: ImageView
    private lateinit var statusTitle: TextView
    private lateinit var statusDetail: TextView
    private lateinit var statusAction: TextView
    private lateinit var clipTitle: TextView
    private lateinit var clipDetail: TextView
    private lateinit var clipSwitch: Switch
    private val onClipboardChanged = ClipboardManager.OnPrimaryClipChangedListener {
        if (Clipboards.sendCurrent(this) == Clipboards.SendResult.SENT) showMessage(getString(R.string.clipboard_sent))
    }
    private lateinit var list: LinearLayout
    private lateinit var message: TextView
    private lateinit var notifTitle: TextView
    private lateinit var notifDetail: TextView
    private lateinit var notifButton: TextView
    private lateinit var notifSwitch: Switch
    private var identity: DeviceIdentity? = null
    private var codeDialog: Dialog? = null
    private var busy = false
    private var shownPcs: List<FoundPc> = emptyList()
    private val onLinkState: (LinkState) -> Unit = { state -> runOnUiThread { showLinkState(state) } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        trusted = TrustedPcs(this)
        discovery = Discovery(this) { pcs -> runOnUiThread { showPcs(pcs) } }
        buildUi()
        showPcs(emptyList())

        worker.execute {
            val id = DeviceIdentity.loadOrCreate()
            Log.i(TAG, "fingerprint ${Hex.encode(id.fingerprint)}")
            identity = id
        }
        // Opening the app reconnects to the paired computer, unless the user disconnected.
        if (trusted.hasAny() && AppSettings.autoConnect(this)) startConnection()
    }

    override fun onResume() {
        super.onResume()
        Link.observe(onLinkState)
        discovery.start()
        refreshNotifications()
        refreshClipboard()
        // While the app is in front, what is copied here goes to the computer.
        getSystemService(ClipboardManager::class.java).addPrimaryClipChangedListener(onClipboardChanged)
    }

    override fun onPause() {
        getSystemService(ClipboardManager::class.java).removePrimaryClipChangedListener(onClipboardChanged)
        discovery.stop()
        Link.stopObserving(onLinkState)
        super.onPause()
    }

    override fun onDestroy() {
        codeDialog?.dismiss()
        worker.shutdown()
        super.onDestroy()
    }

    // ---- Layout ------------------------------------------------------------

    private fun buildUi() {
        drawBehindSystemBars()
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(12), dp(20), dp(56))
        }
        column.addView(Ui.text(this, 28f, medium = true).apply {
            text = getString(R.string.app_name)
            setPadding(0, dp(8), 0, dp(20))
        })
        column.addView(statusCard())

        column.addView(sectionTitle(R.string.computers))
        list = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = Ui.surface(this@MainActivity)
        }
        column.addView(list)
        column.addView(addressSection())

        column.addView(sectionTitle(R.string.notifications))
        column.addView(notificationsCard())
        column.addView(sectionTitle(R.string.clipboard))
        column.addView(clipboardCard())

        message = Ui.text(this, 14f, Ui.TEXT_SECONDARY).apply {
            setPadding(dp(4), dp(12), dp(4), 0)
            visibility = View.GONE
        }
        column.addView(message)

        val scroll = ScrollView(this).apply {
            clipToPadding = false
            addView(column)
        }
        val root = FrameLayout(this).apply {
            background = Ui.backdrop(this@MainActivity)
            addView(scroll)
        }
        root.setOnApplyWindowInsetsListener { _, insets ->
            val (top, bottom) = systemBarInsets(insets)
            scroll.setPadding(0, top, 0, bottom)
            insets
        }
        setContentView(root)
    }

    private fun statusCard(): View {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = Ui.surface(this@MainActivity)
            setPadding(dp(18), dp(18), dp(18), dp(18))
        }
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        statusIcon = ImageView(this).apply {
            background = Ui.surface(this@MainActivity, 14)
            setPadding(dp(10), dp(10), dp(10), dp(10))
        }
        header.addView(statusIcon, LinearLayout.LayoutParams(dp(44), dp(44)))
        val texts = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), 0, 0, 0)
        }
        statusTitle = Ui.text(this, 17f, medium = true)
        statusDetail = Ui.text(this, 14f, Ui.TEXT_SECONDARY).apply { setPadding(0, dp(2), 0, 0) }
        texts.addView(statusTitle)
        texts.addView(statusDetail)
        header.addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        card.addView(header)
        statusAction = Ui.button(this, "", primary = false)
        card.addView(statusAction, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(16)
        })
        return card
    }

    /** Forwarding the phone's notifications: needs system-granted access, then a switch. */
    private fun notificationsCard(): View {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = Ui.surface(this@MainActivity)
            setPadding(dp(18), dp(16), dp(18), dp(16))
        }
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        header.addView(ImageView(this).apply {
            setImageResource(R.drawable.ic_bell)
            imageTintList = android.content.res.ColorStateList.valueOf(Ui.TEXT_SECONDARY)
            background = Ui.surface(this@MainActivity, 14)
            setPadding(dp(10), dp(10), dp(10), dp(10))
        }, LinearLayout.LayoutParams(dp(44), dp(44)))
        val texts = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), 0, dp(8), 0)
        }
        notifTitle = Ui.text(this, 16f, medium = true)
        notifDetail = Ui.text(this, 13f, Ui.TEXT_SECONDARY).apply { setPadding(0, dp(2), 0, 0) }
        texts.addView(notifTitle)
        texts.addView(notifDetail)
        header.addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        notifSwitch = Switch(this).apply {
            val states = arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf())
            thumbTintList = android.content.res.ColorStateList(states, intArrayOf(Ui.ACCENT, Ui.TEXT_SECONDARY))
            trackTintList = android.content.res.ColorStateList(states, intArrayOf(0x66000000 or (Ui.ACCENT and 0xFFFFFF), 0x33FFFFFF))
            setOnCheckedChangeListener { _, checked ->
                AppSettings.setForwardNotifications(this@MainActivity, checked)
                refreshNotifications()
            }
        }
        header.addView(notifSwitch)
        card.addView(header)
        notifButton = Ui.button(this, getString(R.string.allow_access), primary = true).apply {
            setOnClickListener { startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)) }
        }
        card.addView(notifButton, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(14)
        })
        return card
    }

    /** Keeping the clipboard in step with the computer. */
    private fun clipboardCard(): View {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            background = Ui.surface(this@MainActivity)
            setPadding(dp(18), dp(16), dp(18), dp(16))
        }
        card.addView(ImageView(this).apply {
            setImageResource(R.drawable.ic_clipboard)
            imageTintList = android.content.res.ColorStateList.valueOf(Ui.TEXT_SECONDARY)
            background = Ui.surface(this@MainActivity, 14)
            setPadding(dp(10), dp(10), dp(10), dp(10))
        }, LinearLayout.LayoutParams(dp(44), dp(44)))
        val texts = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), 0, dp(8), 0)
        }
        clipTitle = Ui.text(this, 16f, medium = true)
        clipDetail = Ui.text(this, 13f, Ui.TEXT_SECONDARY).apply { setPadding(0, dp(2), 0, 0) }
        texts.addView(clipTitle)
        texts.addView(clipDetail)
        card.addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        clipSwitch = Switch(this).apply {
            val states = arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf())
            thumbTintList = android.content.res.ColorStateList(states, intArrayOf(Ui.ACCENT, Ui.TEXT_SECONDARY))
            trackTintList = android.content.res.ColorStateList(states, intArrayOf(0x66000000 or (Ui.ACCENT and 0xFFFFFF), 0x33FFFFFF))
            setOnCheckedChangeListener { _, checked ->
                AppSettings.setSyncClipboard(this@MainActivity, checked)
                refreshClipboard()
            }
        }
        card.addView(clipSwitch)
        return card
    }

    private fun refreshClipboard() {
        val on = AppSettings.syncClipboard(this)
        if (clipSwitch.isChecked != on) clipSwitch.isChecked = on
        clipTitle.text = getString(if (on) R.string.clipboard_on_title else R.string.clipboard_off_title)
        clipDetail.text = getString(if (on) R.string.clipboard_on_detail else R.string.clipboard_off_detail)
    }

    private fun refreshNotifications() {
        val access = NotificationForwarder.hasAccess(this)
        val forwarding = AppSettings.forwardNotifications(this)
        notifButton.visibility = if (access) View.GONE else View.VISIBLE
        notifSwitch.visibility = if (access) View.VISIBLE else View.GONE
        if (notifSwitch.isChecked != (access && forwarding)) notifSwitch.isChecked = access && forwarding
        val (title, detail) = when {
            !access -> R.string.notifications_off_title to R.string.notifications_off_detail
            forwarding -> R.string.notifications_on_title to R.string.notifications_on_detail
            else -> R.string.notifications_paused_title to R.string.notifications_paused_detail
        }
        notifTitle.text = getString(title)
        notifDetail.text = getString(detail)
    }

    private fun sectionTitle(res: Int) = Ui.text(this, 15f, Ui.TEXT_SECONDARY, medium = true).apply {
        text = getString(res)
        setPadding(dp(4), dp(28), 0, dp(10))
    }

    private fun addressSection(): View {
        val section = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(4), dp(8), dp(4), 0)
        }
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }
        val address = EditText(this).apply {
            hint = getString(R.string.address_hint)
            setHintTextColor(Ui.TEXT_TERTIARY)
            setTextColor(Ui.TEXT)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            isSingleLine = true
            background = Ui.surface(this@MainActivity, 14)
            setPadding(dp(16), dp(13), dp(16), dp(13))
        }
        form.addView(address)
        form.addView(
            Ui.button(this, getString(R.string.connect), primary = true).apply {
                setOnClickListener {
                    parseAddress(address.text.toString())?.let(::connect)
                        ?: showMessage(getString(R.string.invalid_address))
                }
            },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
                .apply { topMargin = dp(10) },
        )
        section.addView(Ui.link(this, getString(R.string.cant_find_computer)).apply {
            setOnClickListener {
                form.visibility = View.VISIBLE
                visibility = View.GONE
                address.requestFocus()
            }
        })
        section.addView(form)
        return section
    }

    private fun showPcs(pcs: List<FoundPc>) {
        shownPcs = pcs
        list.removeAllViews()
        if (pcs.isEmpty()) {
            list.addView(Ui.text(this, 15f, Ui.TEXT_SECONDARY).apply {
                text = getString(R.string.searching)
                setPadding(dp(18), dp(18), dp(18), dp(18))
            })
            return
        }
        pcs.forEachIndexed { index, pc ->
            if (index > 0) {
                list.addView(View(this).apply { setBackgroundColor(0x14FFFFFF) },
                    LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 1).apply { marginStart = dp(64) })
            }
            list.addView(pcRow(pc))
        }
    }

    private fun pcRow(pc: FoundPc) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        background = Ui.pressable(this@MainActivity, null, 20)
        setPadding(dp(18), dp(14), dp(14), dp(14))
        isClickable = true
        setOnClickListener { onPcTapped(pc) }

        addView(ImageView(this@MainActivity).apply {
            setImageResource(R.drawable.ic_computer)
            imageTintList = android.content.res.ColorStateList.valueOf(Ui.TEXT_SECONDARY)
        }, LinearLayout.LayoutParams(dp(28), dp(28)))
        addView(LinearLayout(this@MainActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), 0, dp(8), 0)
            addView(Ui.text(this@MainActivity, 16f, medium = true).apply { text = pc.name })
            addView(Ui.text(this@MainActivity, 13f, Ui.TEXT_TERTIARY).apply { text = pc.host.hostAddress })
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        val paired = trusted.isPaired(pc.id)
        addView(Ui.text(this@MainActivity, 14f, if (paired) Ui.TEXT_SECONDARY else Ui.ACCENT, medium = true).apply {
            text = getString(if (paired) R.string.paired else R.string.pair)
        })
        addView(ImageView(this@MainActivity).apply {
            setImageResource(R.drawable.ic_chevron)
            imageTintList = android.content.res.ColorStateList.valueOf(Ui.TEXT_TERTIARY)
        }, LinearLayout.LayoutParams(dp(20), dp(20)).apply { marginStart = dp(6) })
    }

    private fun showLinkState(state: LinkState) {
        val connected = state is LinkState.Connected
        statusIcon.setImageResource(if (connected) R.drawable.ic_link else R.drawable.ic_computer)
        statusIcon.imageTintList = android.content.res.ColorStateList.valueOf(if (connected) Ui.ACCENT else Ui.TEXT_SECONDARY)
        val pairedName = trusted.names().firstOrNull()
        when (state) {
            is LinkState.Connected -> setStatus(
                getString(R.string.state_connected, state.name),
                getString(R.string.state_connected_address, state.address),
                getString(R.string.disconnect),
            ) { stopConnection() }
            is LinkState.Connecting -> setStatus(getString(R.string.state_connecting, state.name), "", null, null)
            is LinkState.Retrying -> setStatus(
                getString(R.string.state_retrying, state.name),
                getString(R.string.state_retrying_detail, state.seconds),
                getString(R.string.stop),
            ) { stopConnection() }
            LinkState.Searching -> setStatus(
                getString(R.string.state_searching),
                getString(R.string.state_searching_detail),
                getString(R.string.stop),
            ) { stopConnection() }
            LinkState.Off -> if (pairedName == null) {
                setStatus(getString(R.string.state_not_paired), getString(R.string.state_not_paired_detail), null, null)
            } else {
                setStatus(
                    getString(R.string.state_off),
                    getString(R.string.state_off_detail, pairedName),
                    getString(R.string.connect),
                ) { startConnection() }
            }
        }
    }

    private fun setStatus(title: String, detail: String, action: String?, onAction: (() -> Unit)?) {
        statusTitle.text = title
        statusDetail.text = detail
        statusDetail.visibility = if (detail.isEmpty()) View.GONE else View.VISIBLE
        statusAction.visibility = if (action == null) View.GONE else View.VISIBLE
        statusAction.text = action
        statusAction.setOnClickListener { onAction?.invoke() }
    }

    private fun showMessage(text: String) {
        message.text = text
        message.visibility = View.VISIBLE
    }

    // ---- Connection --------------------------------------------------------

    private fun startConnection() {
        AppSettings.setAutoConnect(this, true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            // The connection always shows a notification; ask to be allowed to post it.
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        ConnectionService.start(this)
    }

    private fun stopConnection() {
        AppSettings.setAutoConnect(this, false)
        ConnectionService.stop(this)
    }

    private fun onPcTapped(pc: FoundPc) {
        if (trusted.isPaired(pc.id)) {
            if (Link.state == LinkState.Off) startConnection()
        } else {
            connect(Target(pc.name, pc.host.hostAddress!!, pc.port, pc.id))
        }
    }

    /** `host` or `host:port`; the port defaults to the PC's default. */
    private fun parseAddress(text: String): Target? {
        val trimmed = text.trim()
        if (trimmed.isEmpty() || trimmed.any { it.isWhitespace() }) return null
        val host = trimmed.substringBeforeLast(':', trimmed)
        val port = if (host == trimmed) DEFAULT_PORT else trimmed.substringAfterLast(':').toIntOrNull()
        if (host.isEmpty() || port == null || port !in 1..65535) return null
        return Target(name = trimmed, host = host, port = port, announcedId = null)
    }

    /** Connects to pair with a computer (paired ones are handled by [ConnectionService]). */
    private fun connect(pc: Target) {
        if (busy) return
        busy = true
        showMessage(getString(R.string.connecting, pc.name))
        worker.execute {
            val result = try {
                connectAndPair(pc)
            } catch (e: Exception) {
                Log.w(TAG, "connection to ${pc.host} failed", e)
                getString(R.string.error, e.message ?: e.javaClass.simpleName)
            }
            runOnUiThread {
                codeDialog?.dismiss()
                codeDialog = null
                showMessage(result)
                busy = false
            }
        }
    }

    /** Runs on the worker thread; returns the message to show. */
    private fun connectAndPair(pc: Target): String {
        val id = identity ?: throw IllegalStateException(getString(R.string.identity_not_ready))
        Tls.connect(InetAddress.getByName(pc.host), pc.port, id).use { conn ->
            // The device ID is the start of the fingerprint: the certificate must match the announcement.
            if (pc.announcedId != null && !Hex.encode(conn.peerFingerprint).startsWith(pc.announcedId)) {
                throw PairingException(getString(R.string.certificate_mismatch))
            }
            trusted.nameOf(conn.peerFingerprint)?.let { name ->
                runOnUiThread { startConnection() }
                return getString(R.string.already_paired, name)
            }

            val pairing = Pairing(
                conn.channel,
                { conn.socket.soTimeout = it },
                id.fingerprint,
                conn.peerFingerprint,
                deviceName(),
            )
            val outcome = pairing.run { prompt -> runOnUiThread { showCode(prompt, pairing) } }
            return when (outcome) {
                is PairingOutcome.Paired -> {
                    trusted.add(conn.peerFingerprint, outcome.peerName)
                    runOnUiThread {
                        showPcs(shownPcs)
                        startConnection()
                    }
                    getString(R.string.paired_with, outcome.peerName)
                }
                PairingOutcome.RejectedLocally -> getString(R.string.pairing_cancelled)
                PairingOutcome.RejectedByPeer -> getString(R.string.pairing_rejected_by_pc)
            }
        }
    }

    private fun showCode(prompt: PairingPrompt, pairing: Pairing) {
        val dialog = Dialog(this)
        val blurs = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && windowManager.isCrossWindowBlurEnabled
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = Ui.dialogSurface(this@MainActivity, blurs)
            setPadding(dp(24), dp(24), dp(24), dp(20))
        }
        content.addView(Ui.text(this, 20f, medium = true).apply {
            text = getString(R.string.pair_with, prompt.peerName)
        })
        content.addView(Ui.text(this, 15f, Ui.TEXT_SECONDARY).apply {
            text = getString(R.string.type_code_on_pc)
            setPadding(0, dp(8), 0, dp(20))
        })
        content.addView(Ui.text(this, 40f).apply {
            text = PairingCrypto.formatCode(prompt.code)
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            letterSpacing = 0.08f
            background = Ui.surface(this@MainActivity, 16)
            setPadding(0, dp(16), 0, dp(16))
        })
        content.addView(Ui.text(this, 11f, Ui.TEXT_TERTIARY).apply {
            text = getString(R.string.pc_fingerprint, Hex.encode(prompt.peerFingerprint).chunked(4).joinToString(" "))
            typeface = Typeface.MONOSPACE
            setPadding(0, dp(14), 0, dp(20))
        })
        val buttons = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val weight = { LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f) }
        buttons.addView(Ui.button(this, getString(R.string.cancel), primary = false).apply {
            setOnClickListener { pairing.decide(false); dialog.dismiss() }
        }, weight().apply { marginEnd = dp(6) })
        buttons.addView(Ui.button(this, getString(R.string.accept), primary = true).apply {
            setOnClickListener { pairing.decide(true); dialog.dismiss() }
        }, weight().apply { marginStart = dp(6) })
        content.addView(buttons)

        dialog.setContentView(content)
        dialog.setCancelable(false)
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setLayout(resources.displayMetrics.widthPixels - dp(32), ViewGroup.LayoutParams.WRAP_CONTENT)
            if (blurs) {
                addFlags(WindowManager.LayoutParams.FLAG_BLUR_BEHIND)
                attributes = attributes.apply { blurBehindRadius = dp(24) }
                setDimAmount(0.3f)
            } else {
                setDimAmount(0.65f)
            }
        }
        codeDialog = dialog
        dialog.show()
    }

    // ---- Helpers -----------------------------------------------------------

    @Suppress("DEPRECATION")
    private fun drawBehindSystemBars() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            window.setDecorFitsSystemWindows(false)
        } else {
            window.decorView.systemUiVisibility =
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or
                View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
        }
    }

    @Suppress("DEPRECATION")
    private fun systemBarInsets(insets: WindowInsets): Pair<Int, Int> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
            bars.top to bars.bottom
        } else {
            insets.systemWindowInsetTop to insets.systemWindowInsetBottom
        }

    /** Name shown to the PC: the one set in Android's settings, or the model. */
    private fun deviceName(): String =
        Settings.Global.getString(contentResolver, Settings.Global.DEVICE_NAME)
            ?.takeIf { it.isNotBlank() } ?: Build.MODEL

    private fun dp(value: Int): Int = Ui.dp(this, value)

    /** Where to connect: a PC found on the network (with its announced ID) or typed by the user. */
    private data class Target(val name: String, val host: String, val port: Int, val announcedId: String?)

    companion object {
        private const val TAG = "Kizuna"
        private const val DEFAULT_PORT = 47820
    }
}
