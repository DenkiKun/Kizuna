package io.github.denkikun.kizuna

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.net.InetAddress
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val worker = Executors.newSingleThreadExecutor()
    private lateinit var trusted: TrustedPcs
    private lateinit var discovery: Discovery
    private lateinit var list: LinearLayout
    private lateinit var status: TextView
    private var identity: DeviceIdentity? = null
    private var codeDialog: AlertDialog? = null
    private var busy = false
    private var shownPcs: List<FoundPc> = emptyList()

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
    }

    override fun onResume() {
        super.onResume()
        discovery.start()
    }

    override fun onPause() {
        discovery.stop()
        super.onPause()
    }

    override fun onDestroy() {
        codeDialog?.dismiss()
        worker.shutdown()
        super.onDestroy()
    }

    private fun buildUi() {
        val pad = dp(24)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        column.addView(TextView(this).apply {
            text = getString(R.string.app_name)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 32f)
            typeface = Typeface.DEFAULT_BOLD
        })
        column.addView(TextView(this).apply {
            text = getString(R.string.pcs_on_network)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setPadding(0, dp(16), 0, dp(8))
        })
        list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        column.addView(list)

        // Fallback for networks that block multicast (mDNS): connect by address.
        column.addView(TextView(this).apply {
            text = getString(R.string.connect_by_address)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setPadding(0, dp(24), 0, dp(8))
        })
        val address = EditText(this).apply {
            hint = getString(R.string.address_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            isSingleLine = true
        }
        column.addView(address)
        column.addView(Button(this).apply {
            text = getString(R.string.connect)
            setOnClickListener {
                parseAddress(address.text.toString())?.let(::connect)
                    ?: run { status.text = getString(R.string.invalid_address) }
            }
        })
        status = TextView(this).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
            setPadding(0, dp(24), 0, 0)
        }
        column.addView(status)
        setContentView(ScrollView(this).apply {
            fitsSystemWindows = true
            addView(column)
        })
    }

    private fun showPcs(pcs: List<FoundPc>) {
        shownPcs = pcs
        list.removeAllViews()
        if (pcs.isEmpty()) {
            list.addView(TextView(this).apply { text = getString(R.string.searching) })
            return
        }
        for (pc in pcs) {
            val paired = trusted.isPaired(pc.id)
            list.addView(Button(this).apply {
                isAllCaps = false
                gravity = Gravity.START or Gravity.CENTER_VERTICAL
                text = getString(
                    if (paired) R.string.pc_entry_paired else R.string.pc_entry,
                    pc.name,
                    pc.host.hostAddress,
                )
                setOnClickListener { connect(pc) }
            })
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

    private fun connect(pc: FoundPc) =
        connect(Target(pc.name, pc.host.hostAddress!!, pc.port, pc.id))

    private fun connect(pc: Target) {
        if (busy) return
        busy = true
        status.text = getString(R.string.connecting, pc.name)
        worker.execute {
            val message = try {
                connectAndPair(pc)
            } catch (e: Exception) {
                Log.w(TAG, "connection to ${pc.host} failed", e)
                getString(R.string.error, e.message ?: e.javaClass.simpleName)
            }
            runOnUiThread {
                codeDialog?.dismiss()
                codeDialog = null
                status.text = message
                busy = false
            }
        }
    }

    /** Runs on the worker thread; returns the status to show. */
    private fun connectAndPair(pc: Target): String {
        val id = identity ?: throw IllegalStateException(getString(R.string.identity_not_ready))
        Tls.connect(InetAddress.getByName(pc.host), pc.port, id).use { conn ->
            // The device ID is the start of the fingerprint: the certificate must match the announcement.
            if (pc.announcedId != null && !Hex.encode(conn.peerFingerprint).startsWith(pc.announcedId)) {
                throw PairingException(getString(R.string.certificate_mismatch))
            }
            trusted.nameOf(conn.peerFingerprint)?.let { name ->
                return getString(R.string.connected_paired, name)
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
                    runOnUiThread { showPcs(shownPcs) }
                    getString(R.string.paired_with, outcome.peerName)
                }
                PairingOutcome.RejectedLocally -> getString(R.string.pairing_cancelled)
                PairingOutcome.RejectedByPeer -> getString(R.string.pairing_rejected_by_pc)
            }
        }
    }

    private fun showCode(prompt: PairingPrompt, pairing: Pairing) {
        val pad = dp(24)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, dp(8), pad, 0)
        }
        content.addView(TextView(this).apply {
            text = PairingCrypto.formatCode(prompt.code)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 40f)
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            setPadding(0, dp(8), 0, dp(16))
        })
        content.addView(TextView(this).apply {
            text = getString(R.string.type_code_on_pc)
        })
        content.addView(TextView(this).apply {
            text = getString(R.string.pc_fingerprint, Hex.encode(prompt.peerFingerprint).chunked(4).joinToString(" "))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            typeface = Typeface.MONOSPACE
            setPadding(0, dp(16), 0, 0)
        })
        codeDialog = AlertDialog.Builder(this)
            .setTitle(getString(R.string.pair_with, prompt.peerName))
            .setView(content)
            .setCancelable(false)
            .setPositiveButton(R.string.accept) { _, _ -> pairing.decide(true) }
            .setNegativeButton(R.string.reject) { _, _ -> pairing.decide(false) }
            .show()
    }

    /** Name shown to the PC: the one set in Android's settings, or the model. */
    private fun deviceName(): String =
        Settings.Global.getString(contentResolver, Settings.Global.DEVICE_NAME)
            ?.takeIf { it.isNotBlank() } ?: Build.MODEL

    private fun dp(value: Int): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics).toInt()

    /** Where to connect: a PC found over mDNS (with its announced ID) or typed by the user. */
    private data class Target(val name: String, val host: String, val port: Int, val announcedId: String?)

    companion object {
        private const val TAG = "Kizuna"
        private const val DEFAULT_PORT = 47820
    }
}
