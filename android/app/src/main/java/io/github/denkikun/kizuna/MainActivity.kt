package io.github.denkikun.kizuna

import android.app.Activity
import android.app.Dialog
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
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
import android.widget.ProgressBar
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
    private var codeDialog: Dialog? = null
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
        drawBehindSystemBars()
        val pad = dp(20)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }

        column.addView(Ui.text(this, 34f, bold = true).apply { text = getString(R.string.app_name) })
        column.addView(Ui.text(this, 15f, Ui.TEXT_SECONDARY).apply {
            text = getString(R.string.tagline)
            setPadding(0, dp(4), 0, dp(28))
        })

        column.addView(sectionTitle(R.string.pcs_on_network))
        list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        column.addView(list)

        // Fallback for networks where neither mDNS nor broadcast works: connect by address.
        column.addView(sectionTitle(R.string.connect_by_address).apply { setPadding(0, dp(28), 0, dp(10)) })
        val addressCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = Ui.card(this@MainActivity)
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }
        val address = EditText(this).apply {
            hint = getString(R.string.address_hint)
            setHintTextColor(Ui.TEXT_HINT)
            setTextColor(Ui.TEXT)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            isSingleLine = true
            background = Ui.card(this@MainActivity, 16, 0x14FFFFFF)
            setPadding(dp(16), dp(14), dp(16), dp(14))
        }
        addressCard.addView(address)
        addressCard.addView(
            Ui.button(this, getString(R.string.connect), accent = true).apply {
                setOnClickListener {
                    parseAddress(address.text.toString())?.let(::connect)
                        ?: run { setStatus(getString(R.string.invalid_address)) }
                }
            },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
                .apply { topMargin = dp(12) },
        )
        column.addView(addressCard)

        status = Ui.text(this, 15f).apply {
            background = Ui.card(this@MainActivity, 20, 0x2BFFFFFF)
            setPadding(dp(18), dp(14), dp(18), dp(14))
            visibility = View.GONE
        }
        column.addView(
            status,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
                .apply { topMargin = dp(20) },
        )

        val scroll = ScrollView(this).apply {
            isFillViewport = true
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

    private fun sectionTitle(res: Int) = Ui.text(this, 13f, Ui.TEXT_SECONDARY, bold = true).apply {
        text = getString(res).uppercase()
        letterSpacing = 0.08f
        setPadding(0, 0, 0, dp(10))
    }

    private fun showPcs(pcs: List<FoundPc>) {
        shownPcs = pcs
        list.removeAllViews()
        if (pcs.isEmpty()) {
            list.addView(searchingCard())
            return
        }
        for (pc in pcs) {
            list.addView(
                pcCard(pc),
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
                    .apply { bottomMargin = dp(10) },
            )
        }
    }

    private fun searchingCard() = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        background = Ui.card(this@MainActivity)
        setPadding(dp(18), dp(18), dp(18), dp(18))
        addView(ProgressBar(this@MainActivity).apply {
            isIndeterminate = true
            indeterminateTintList = ColorStateList.valueOf(Ui.TEXT)
        }, LinearLayout.LayoutParams(dp(22), dp(22)))
        addView(Ui.text(this@MainActivity, 15f, Ui.TEXT_SECONDARY).apply {
            text = getString(R.string.searching)
            setPadding(dp(14), 0, 0, 0)
        })
    }

    private fun pcCard(pc: FoundPc) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        background = Ui.pressableCard(this@MainActivity)
        setPadding(dp(16), dp(16), dp(16), dp(16))
        isClickable = true
        setOnClickListener { connect(pc) }

        addView(ImageView(this@MainActivity).apply {
            setImageResource(R.drawable.ic_pc)
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(0x26FFFFFF)
            }
            setPadding(dp(10), dp(10), dp(10), dp(10))
        }, LinearLayout.LayoutParams(dp(46), dp(46)))

        addView(LinearLayout(this@MainActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), 0, dp(8), 0)
            addView(Ui.text(this@MainActivity, 17f, bold = true).apply { text = pc.name })
            addView(Ui.text(this@MainActivity, 13f, Ui.TEXT_SECONDARY).apply {
                text = pc.host.hostAddress
                typeface = Typeface.MONOSPACE
            })
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))

        if (trusted.isPaired(pc.id)) {
            addView(Ui.text(this@MainActivity, 12f, Ui.ACCENT, bold = true).apply {
                text = getString(R.string.paired)
                background = GradientDrawable().apply {
                    cornerRadius = dp(12).toFloat()
                    setColor(0x26FF8F73)
                    setStroke(dp(1), 0x59FF8F73)
                }
                setPadding(dp(10), dp(4), dp(10), dp(4))
            })
        }
    }

    private fun setStatus(text: String) {
        status.text = text
        status.visibility = View.VISIBLE
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
        setStatus(getString(R.string.connecting, pc.name))
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
                setStatus(message)
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
        val dialog = Dialog(this)
        val blurs = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && windowManager.isCrossWindowBlurEnabled
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            // More opaque when the system cannot blur what is behind the dialog.
            background = Ui.card(this@MainActivity, 28, if (blurs) 0x59241E5C else 0xF2241E5C.toInt())
            setPadding(dp(24), dp(24), dp(24), dp(20))
        }
        content.addView(Ui.text(this, 20f, bold = true).apply {
            text = getString(R.string.pair_with, prompt.peerName)
        })
        content.addView(Ui.text(this, 44f, bold = true).apply {
            text = PairingCrypto.formatCode(prompt.code)
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            letterSpacing = 0.05f
            setPadding(0, dp(20), 0, dp(16))
        })
        content.addView(Ui.text(this, 15f, Ui.TEXT_SECONDARY).apply {
            text = getString(R.string.type_code_on_pc)
        })
        content.addView(Ui.text(this, 11f, Ui.TEXT_HINT).apply {
            text = getString(R.string.pc_fingerprint, Hex.encode(prompt.peerFingerprint).chunked(4).joinToString(" "))
            typeface = Typeface.MONOSPACE
            setPadding(0, dp(16), 0, dp(20))
        })
        val buttons = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val weight = { LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f) }
        buttons.addView(Ui.button(this, getString(R.string.reject), accent = false).apply {
            setOnClickListener { pairing.decide(false); dialog.dismiss() }
        }, weight().apply { marginEnd = dp(6) })
        buttons.addView(Ui.button(this, getString(R.string.accept), accent = true).apply {
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
                attributes = attributes.apply { blurBehindRadius = dp(28) }
                setDimAmount(0.25f)
            } else {
                setDimAmount(0.6f)
            }
        }
        codeDialog = dialog
        dialog.show()
    }

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
