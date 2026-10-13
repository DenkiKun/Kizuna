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

/** Colors, shapes and text styles of the app. */
object Ui {
    const val TEXT = 0xFFF3F4F6.toInt()
    const val TEXT_SECONDARY = 0xFFA1A6B0.toInt()
    const val TEXT_TERTIARY = 0xFF6B7079.toInt()
    const val ACCENT = 0xFF8B85FF.toInt()
    const val SUCCESS = 0xFF4ADE80.toInt()

    private const val SURFACE = 0x0FFFFFFF
    private const val SURFACE_STRONG = 0xF21A1C22.toInt()
    private const val HAIRLINE = 0x1AFFFFFF
    private const val RIPPLE = 0x1FFFFFFF

    fun dp(context: Context, value: Number): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), context.resources.displayMetrics).toInt()

    /** Neutral background with a faint light at the top. */
    fun backdrop(context: Context): Drawable {
        val base = GradientDrawable(
            GradientDrawable.Orientation.TOP_BOTTOM,
            intArrayOf(0xFF14161C.toInt(), 0xFF0B0C10.toInt()),
        )
        val light = GradientDrawable().apply {
            gradientType = GradientDrawable.RADIAL_GRADIENT
            colors = intArrayOf(0x14FFFFFF, 0x00FFFFFF)
            setGradientCenter(0.5f, 0f)
            gradientRadius = context.resources.displayMetrics.widthPixels * 0.9f
        }
        return LayerDrawable(arrayOf(base, light))
    }

    /** Translucent surface with a hairline border. */
    fun surface(context: Context, radiusDp: Int = 20, fill: Int = SURFACE): GradientDrawable =
        GradientDrawable().apply {
            cornerRadius = dp(context, radiusDp).toFloat()
            setColor(fill)
            setStroke(dp(context, 1), HAIRLINE)
        }

    /** Surface for dialogs: nearly opaque when the system cannot blur behind it. */
    fun dialogSurface(context: Context, blurred: Boolean): GradientDrawable =
        surface(context, 24, if (blurred) 0xB31A1C22.toInt() else SURFACE_STRONG)

    fun pressable(context: Context, base: Drawable?, radiusDp: Int): Drawable {
        val mask = GradientDrawable().apply {
            cornerRadius = dp(context, radiusDp).toFloat()
            setColor(Color.WHITE)
        }
        return RippleDrawable(ColorStateList.valueOf(RIPPLE), base, mask)
    }

    fun text(context: Context, sizeSp: Float, color: Int = TEXT, medium: Boolean = false) = TextView(context).apply {
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp)
        setTextColor(color)
        if (medium) typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
    }

    /** Primary (filled with the accent) or secondary (outlined) button. */
    fun button(context: Context, label: String, primary: Boolean) = text(context, 15f, medium = true).apply {
        text = label
        gravity = Gravity.CENTER
        minHeight = dp(context, 46)
        setPadding(dp(context, 20), 0, dp(context, 20), 0)
        val shape = GradientDrawable().apply {
            cornerRadius = dp(context, 14).toFloat()
            if (primary) setColor(ACCENT) else setStroke(dp(context, 1), 0x33FFFFFF)
        }
        if (primary) setTextColor(0xFF0E0F14.toInt())
        background = pressable(context, shape, 14)
        isClickable = true
        isFocusable = true
    }

    /** Text-only button in the accent color. */
    fun link(context: Context, label: String) = text(context, 15f, ACCENT, medium = true).apply {
        text = label
        setPadding(0, dp(context, 12), 0, dp(context, 12))
        background = pressable(context, null, 8)
        isClickable = true
        isFocusable = true
    }

    fun dot(context: Context, color: Int): GradientDrawable = GradientDrawable().apply {
        shape = GradientDrawable.OVAL
        setColor(color)
        setSize(dp(context, 8), dp(context, 8))
    }
}
