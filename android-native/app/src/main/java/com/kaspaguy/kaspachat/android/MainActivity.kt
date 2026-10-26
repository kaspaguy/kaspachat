package com.kaspaguy.kaspachat.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavBackStackEntry
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.navigation
import androidx.navigation.compose.rememberNavController
import com.kaspaguy.kaspachat.android.security.SeedVault
import com.kaspaguy.kaspachat.android.security.Session
import com.kaspaguy.kaspachat.android.ui.home.HomeScreen
import com.kaspaguy.kaspachat.android.ui.onboarding.ConfirmPhraseScreen
import com.kaspaguy.kaspachat.android.ui.onboarding.OnboardingViewModel
import com.kaspaguy.kaspachat.android.ui.onboarding.PasscodeScreen
import com.kaspaguy.kaspachat.android.ui.onboarding.RestoreScreen
import com.kaspaguy.kaspachat.android.ui.onboarding.ShowPhraseScreen
import com.kaspaguy.kaspachat.android.ui.onboarding.UnlockScreen
import com.kaspaguy.kaspachat.android.ui.onboarding.WelcomeScreen
import com.kaspaguy.kaspachat.android.ui.theme.KaspaChatTheme
import com.kaspaguy.kaspachat.android.ui.topup.PaymentScreen
import com.kaspaguy.kaspachat.android.ui.topup.TopUpScreen
import org.koin.android.ext.android.inject
import org.koin.compose.viewmodel.koinViewModel
import org.koin.core.parameter.parametersOf

class MainActivity : ComponentActivity() {
    private val vault: SeedVault by inject()
    private val session: Session by inject()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            KaspaChatTheme { AppNav(vault, session) }
        }
    }
}

private object Routes {
    const val WELCOME = "welcome"
    const val ONBOARDING = "onboarding"
    const val ONBOARDING_GRAPH = "onboarding/{mode}"
    const val PHRASE = "phrase"
    const val CONFIRM = "confirm"
    const val RESTORE = "restore"
    const val PASSCODE = "passcode"
    const val UNLOCK = "unlock"
    const val HOME = "home"
    const val TOPUP = "topup"
    const val PAYMENT = "payment/{id}"
    fun payment(id: String) = "payment/$id"
}

@Composable
private fun AppNav(vault: SeedVault, session: Session) {
    val nav = rememberNavController()
    val state by session.state.collectAsStateWithLifecycle()
    // Fixed once: a changing start destination would rebuild the graph (and cancel onboarding) when the session opens.
    val start = remember {
        when {
            session.state.value is Session.State.Unlocked -> Routes.HOME
            vault.exists -> Routes.UNLOCK
            else -> Routes.WELCOME
        }
    }
    // Auto-lock (or a lock from anywhere) returns to the unlock screen and drops everything behind it.
    LaunchedEffect(state) {
        val route = nav.currentDestination?.route
        if (state is Session.State.Locked && vault.exists && route in setOf(Routes.HOME, Routes.TOPUP, Routes.PAYMENT)) nav.resetTo(Routes.UNLOCK)
    }

    NavHost(nav, startDestination = start) {
        composable(Routes.WELCOME) {
            WelcomeScreen(onCreate = { nav.navigate("${Routes.ONBOARDING}/create") }, onRestore = { nav.navigate("${Routes.ONBOARDING}/restore") })
        }
        navigation(startDestination = Routes.PHRASE, route = Routes.ONBOARDING_GRAPH) {
            composable(Routes.PHRASE) { entry ->
                val parent = remember(entry) { nav.getBackStackEntry(Routes.ONBOARDING_GRAPH) }
                val vm: OnboardingViewModel = koinViewModel(viewModelStoreOwner = parent)
                LaunchedEffect(Unit) {
                    if (parent.arguments?.getString("mode") == "restore") nav.navigate(Routes.RESTORE) { popUpTo(Routes.PHRASE) { inclusive = true } }
                }
                if (parent.arguments?.getString("mode") != "restore") ShowPhraseScreen(vm) { nav.navigate(Routes.CONFIRM) }
            }
            composable(Routes.CONFIRM) { entry ->
                val vm = onboardingVm(nav, entry)
                ConfirmPhraseScreen(vm, onBack = { nav.popBackStack() }, onConfirmed = { nav.navigate(Routes.PASSCODE) })
            }
            composable(Routes.RESTORE) { entry ->
                val vm = onboardingVm(nav, entry)
                RestoreScreen(vm) { nav.navigate(Routes.PASSCODE) }
            }
            composable(Routes.PASSCODE) { entry ->
                val vm = onboardingVm(nav, entry)
                PasscodeScreen(vm) { nav.resetTo(Routes.HOME) }
            }
        }
        composable(Routes.UNLOCK) {
            UnlockScreen(koinViewModel(), onUnlocked = { nav.resetTo(Routes.HOME) }, onRestore = { nav.resetTo(Routes.WELCOME) })
        }
        composable(Routes.HOME) {
            HomeScreen(
                koinViewModel(),
                onTopUp = { nav.navigate(Routes.TOPUP) },
                onOrder = { nav.navigate(Routes.payment(it)) },
                onLocked = { nav.resetTo(Routes.UNLOCK) },
            )
        }
        composable(Routes.TOPUP) {
            TopUpScreen(koinViewModel()) { id -> nav.navigate(Routes.payment(id)) { popUpTo(Routes.HOME) } }
        }
        composable(Routes.PAYMENT) { entry ->
            val id = entry.arguments?.getString("id").orEmpty()
            PaymentScreen(koinViewModel(key = id) { parametersOf(id) }) { nav.popBackStack(Routes.HOME, inclusive = false) }
        }
    }
}

// The onboarding screens share one view model, scoped to the onboarding graph's back stack entry.
@Composable
private fun onboardingVm(nav: NavHostController, entry: NavBackStackEntry): OnboardingViewModel {
    val parent = remember(entry) { nav.getBackStackEntry(Routes.ONBOARDING_GRAPH) }
    return koinViewModel(viewModelStoreOwner = parent)
}

private fun NavHostController.resetTo(route: String) = navigate(route) {
    popUpTo(graph.id) { inclusive = true }
    launchSingleTop = true
}
