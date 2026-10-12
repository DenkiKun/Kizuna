package io.github.denkikun.kizuna

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.LayerDrawable
import android.graphics.drawable.RippleDrawable
import android.util.TypedValue
import android.view.Gravity
import android.widget.TextView

/** Colors and drawables of the app's translucent look. */
object Ui {
    const val TEXT = Color.WHITE
    const val TEXT_SECONDARY = 0xB3FFFFFF.toInt()
    const val TEXT_HINT = 0x80FFFFFF.toInt()
    const val ACCENT = 0xFFFF8F73.toInt()
    private const val ACCENT_DEEP = 0xFFF0607A.toInt()

    private const val CARD_FILL = 0x1FFFFFFF
    private const val CARD_STROKE = 0x40FFFFFF
    private const val SHEEN = 0x26FFFFFF
    private const val RIPPLE = 0x33FFFFFF

    fun dp(context: Context, value: Number): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), context.resources.displayMetrics).toInt()

    /** Deep gradient with soft color glows, behind everything. */
    fun backdrop(context: Context): Drawable {
        val width = context.resources.displayMetrics.widthPixels.toFloat()
        val base = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(0xFF120F2E.toInt(), 0xFF1E1850.toInt(), 0xFF0C2C3E.toInt()),
        )
        fun glow(color: Int, x: Float, y: Float, radius: Float) = GradientDrawable().apply {
            gradientType = GradientDrawable.RADIAL_GRADIENT
            colors = intArrayOf(color, color and 0x00FFFFFF)
            setGradientCenter(x, y)
            gradientRadius = radius * width
        }
        return LayerDrawable(
            arrayOf(
                base,
                glow(0x997C6CFF.toInt(), 0.1f, 0.08f, 0.9f),
                glow(0x80FF8F73.toInt(), 0.95f, 0.35f, 0.75f),
                glow(0x702FD3C4, 0.2f, 0.85f, 0.85f),
            ),
        )
    }

    /** Translucent card: light fill, hairline border and a sheen at the top. */
    fun card(context: Context, radiusDp: Int = 24, fill: Int = CARD_FILL): Drawable {
        val radius = dp(context, radiusDp).toFloat()
        val body = GradientDrawable().apply {
            cornerRadius = radius
            setColor(fill)
            setStroke(dp(context, 1), CARD_STROKE)
        }
        val sheen = GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, intArrayOf(SHEEN, 0)).apply {
            cornerRadius = radius
        }
        return LayerDrawable(arrayOf(body, sheen))
    }

    /** A card that shows a ripple when pressed. */
    fun pressableCard(context: Context, radiusDp: Int = 24, fill: Int = CARD_FILL): Drawable {
        val mask = GradientDrawable().apply {
            cornerRadius = dp(context, radiusDp).toFloat()
            setColor(Color.WHITE)
        }
        return RippleDrawable(ColorStateList.valueOf(RIPPLE), card(context, radiusDp, fill), mask)
    }

    /** Filled pill for the main action. */
    fun accentPill(context: Context): Drawable {
        val pill = GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT, intArrayOf(ACCENT, ACCENT_DEEP)).apply {
            cornerRadius = dp(context, 28).toFloat()
        }
        val mask = GradientDrawable().apply {
            cornerRadius = dp(context, 28).toFloat()
            setColor(Color.WHITE)
        }
        return RippleDrawable(ColorStateList.valueOf(RIPPLE), pill, mask)
    }

    fun text(context: Context, sizeSp: Float, color: Int = TEXT, bold: Boolean = false) = TextView(context).apply {
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp)
        setTextColor(color)
        if (bold) typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
    }

    /** Pill-shaped button; `accent` for the main action. */
    fun button(context: Context, label: String, accent: Boolean) = text(context, 16f, bold = true).apply {
        text = label
        gravity = Gravity.CENTER
        minHeight = dp(context, 52)
        setPadding(dp(context, 24), 0, dp(context, 24), 0)
        background = if (accent) accentPill(context) else pressableCard(context, 28)
        isClickable = true
        isFocusable = true
    }
}
