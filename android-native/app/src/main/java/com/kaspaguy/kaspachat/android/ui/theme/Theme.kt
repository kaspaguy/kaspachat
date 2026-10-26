package com.kaspaguy.kaspachat.android.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val Teal = Color(0xFF49EACB)
private val TealDark = Color(0xFF0E7C6B)

private val Light = lightColorScheme(primary = TealDark, onPrimary = Color.White, secondary = Color(0xFF3B5B57))
private val Dark = darkColorScheme(primary = Teal, onPrimary = Color(0xFF00382F), secondary = Color(0xFFA9CEC7))

@Composable
fun KaspaChatTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) Dark else Light, content = content)
}
