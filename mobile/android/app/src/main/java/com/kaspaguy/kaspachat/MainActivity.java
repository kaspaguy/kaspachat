package com.kaspaguy.kaspachat;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    private Activity.ScreenCaptureCallback captureCallback;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(KaspaChatNativePlugin.class);
        super.onCreate(savedInstanceState);
    }

    // Android 14+: told when the user takes a screenshot with the device's buttons while this screen is visible.
    @Override
    public void onStart() {
        super.onStart();
        if (Build.VERSION.SDK_INT >= 34) {
            captureCallback = () -> KaspaChatNativePlugin.screenshot();
            registerScreenCaptureCallback(getMainExecutor(), captureCallback);
        }
    }

    @Override
    public void onStop() {
        if (Build.VERSION.SDK_INT >= 34 && captureCallback != null) unregisterScreenCaptureCallback(captureCallback);
        super.onStop();
    }
}
