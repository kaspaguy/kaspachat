package com.kaspaguy.kaspachat.android.ui.common

import android.graphics.Bitmap
import android.view.WindowManager
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.kaspaguy.kaspachat.android.payment.QrCode

/**
 * Blocks screenshots, screen recording and the recents thumbnail while on screen (FLAG_SECURE): the recovery phrase,
 * and chats with screenshot protection on. Counted, so nested secure screens don't clear each other's flag.
 */
@Composable
fun SecureWindow() {
    val window = LocalActivity.current?.window ?: return
    DisposableEffect(window) {
        if (SecureCount.n++ == 0) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { if (--SecureCount.n == 0) window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
}

private object SecureCount {
    var n = 0
}

@Composable
fun Screen(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier
                .safeDrawingPadding()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            content = content,
        )
    }
}

@Composable
fun ErrorText(msg: String?) {
    if (msg != null) Text(msg, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
}

/** A QR code, black on white whatever the theme (wallet scanners expect it), pixel-exact when scaled. */
@Composable
fun QrImage(text: String, size: Dp, description: String) {
    val bitmap = remember(text) {
        val m = QrCode.encode(text)
        val px = IntArray(m.width * m.height) { if (m.get(it % m.width, it / m.width)) 0xff000000.toInt() else 0xffffffff.toInt() }
        Bitmap.createBitmap(px, m.width, m.height, Bitmap.Config.ARGB_8888).asImageBitmap()
    }
    Box(Modifier.clip(RoundedCornerShape(12.dp)).background(Color.White).padding(8.dp)) {
        Image(
            bitmap = bitmap,
            contentDescription = null,
            filterQuality = FilterQuality.None,
            modifier = Modifier.size(size).semantics { contentDescription = description },
        )
    }
}
