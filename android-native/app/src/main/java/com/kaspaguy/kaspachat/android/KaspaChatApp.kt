package com.kaspaguy.kaspachat.android

import android.app.Application
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.kaspaguy.kaspachat.android.data.local.DatabaseHolder
import com.kaspaguy.kaspachat.android.data.remote.Network
import com.kaspaguy.kaspachat.android.domain.AccountRepository
import com.kaspaguy.kaspachat.android.domain.PaymentRepository
import com.kaspaguy.kaspachat.android.security.SeedVault
import com.kaspaguy.kaspachat.android.security.Session
import com.kaspaguy.kaspachat.android.ui.home.HomeViewModel
import com.kaspaguy.kaspachat.android.ui.onboarding.OnboardingViewModel
import com.kaspaguy.kaspachat.android.ui.onboarding.UnlockViewModel
import com.kaspaguy.kaspachat.android.ui.topup.PaymentViewModel
import com.kaspaguy.kaspachat.android.ui.topup.TopUpViewModel
import org.koin.android.ext.android.inject
import org.koin.android.ext.koin.androidContext
import org.koin.core.context.startKoin
import org.koin.core.module.dsl.viewModel
import org.koin.core.module.dsl.viewModelOf
import org.koin.dsl.module

val appModule = module {
    single { SeedVault(get()) }
    single { DatabaseHolder(get()) }
    single { Session(get()) }
    single { Network.relay() }
    single { Network.indexer() }
    single { AccountRepository(get(), get(), get(), get()) }
    single { PaymentRepository(get(), get(), get(), get()) }
    viewModelOf(::OnboardingViewModel)
    viewModelOf(::UnlockViewModel)
    viewModelOf(::HomeViewModel)
    viewModelOf(::TopUpViewModel)
    viewModel { p -> PaymentViewModel(p.get(), get()) }
}

class KaspaChatApp : Application() {
    private val session: Session by inject()

    override fun onCreate() {
        super.onCreate()
        startKoin {
            androidContext(this@KaspaChatApp)
            modules(appModule)
        }
        // Lock (wipe the seed, close the database) after five minutes in the background.
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            private var backgroundSince = 0L
            override fun onStop(owner: LifecycleOwner) {
                backgroundSince = System.currentTimeMillis()
            }
            override fun onStart(owner: LifecycleOwner) {
                if (backgroundSince != 0L && System.currentTimeMillis() - backgroundSince > AUTO_LOCK_MS) session.lock()
                backgroundSince = 0L
            }
        })
    }

    private companion object {
        const val AUTO_LOCK_MS = 5 * 60_000L
    }
}
