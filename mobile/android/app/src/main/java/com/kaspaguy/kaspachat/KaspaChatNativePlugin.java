package com.kaspaguy.kaspachat;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.PowerManager;
import android.provider.Settings;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

// Keeps KaspaChat running in the background (no Google push: Google would learn when a device gets a message),
// reports screenshots to the web layer, and makes the app's requests through Tor (PROTOCOL_SPEC §6.3).
@CapacitorPlugin(name = "KaspaChatNative")
public class KaspaChatNativePlugin extends Plugin {
    private static KaspaChatNativePlugin instance;
    private static final ExecutorService net = Executors.newCachedThreadPool();
    private static int torPort = 0;

    @Override
    public void load() {
        instance = this;
    }

    static void screenshot() {
        if (instance != null) instance.notifyListeners("screenshot", new JSObject());
    }

    @PluginMethod
    public void startKeepAlive(PluginCall call) {
        Context c = getContext();
        Intent i = new Intent(c, KeepAliveService.class);
        if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i);
        else c.startService(i);
        call.resolve();
    }

    @PluginMethod
    public void stopKeepAlive(PluginCall call) {
        getContext().stopService(new Intent(getContext(), KeepAliveService.class));
        call.resolve();
    }

    @PluginMethod
    public void batteryStatus(PluginCall call) {
        PowerManager pm = (PowerManager) getContext().getSystemService(Context.POWER_SERVICE);
        JSObject r = new JSObject();
        r.put("ignoring", pm.isIgnoringBatteryOptimizations(getContext().getPackageName()));
        call.resolve(r);
    }

    // Shows Android's own "let this app run in the background?" dialog.
    @SuppressLint("BatteryLife")
    @PluginMethod
    public void requestBatteryExemption(PluginCall call) {
        Intent i = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:" + getContext().getPackageName()));
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        getContext().startActivity(i);
        call.resolve();
    }
    // Starts Tor once; later calls get the same port.
    @PluginMethod
    public void torStart(PluginCall call) {
        String host = call.getString("host", "");
        File dir = new File(getContext().getFilesDir(), "tor");
        net.execute(() -> {
            int port;
            synchronized (TorBridge.class) {
                if (torPort == 0) {
                    int p = TorBridge.start(dir.getPath(), host);
                    if (p > 0) torPort = p;
                    else {
                        call.reject(TorBridge.error());
                        return;
                    }
                }
                port = torPort;
            }
            JSObject r = new JSObject();
            r.put("port", port);
            call.resolve(r);
        });
    }

    // One request through the SOCKS port. The onion host is resolved by Tor, never by the phone's DNS.
    @PluginMethod
    public void torFetch(PluginCall call) {
        int port = call.getInt("port", 0);
        String url = call.getString("url");
        String method = call.getString("method", "GET");
        JSObject headers = call.getObject("headers", new JSObject());
        String body = call.getString("body");
        net.execute(() -> {
            HttpURLConnection c = null;
            try {
                c = (HttpURLConnection) new URL(url).openConnection(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", port)));
                c.setConnectTimeout(60_000);
                c.setReadTimeout(120_000);
                c.setUseCaches(false);
                c.setRequestMethod(method);
                for (Iterator<String> k = headers.keys(); k.hasNext(); ) {
                    String n = k.next();
                    c.setRequestProperty(n, headers.getString(n));
                }
                if (body != null) {
                    c.setDoOutput(true);
                    try (OutputStream o = c.getOutputStream()) {
                        o.write(body.getBytes(StandardCharsets.UTF_8));
                    }
                }
                int status = c.getResponseCode();
                InputStream in = status >= 400 ? c.getErrorStream() : c.getInputStream();
                ByteArrayOutputStream b = new ByteArrayOutputStream();
                if (in != null) {
                    try (InputStream i = in) {
                        byte[] buf = new byte[16384];
                        for (int n; (n = i.read(buf)) > 0; ) b.write(buf, 0, n);
                    }
                }
                JSObject h = new JSObject();
                for (Map.Entry<String, List<String>> e : c.getHeaderFields().entrySet()) {
                    if (e.getKey() != null && !e.getValue().isEmpty()) h.put(e.getKey().toLowerCase(), e.getValue().get(0));
                }
                JSObject r = new JSObject();
                r.put("status", status);
                r.put("headers", h);
                r.put("body", b.toString("UTF-8"));
                call.resolve(r);
            } catch (Exception e) {
                call.reject("Tor request failed: " + e.getMessage());
            } finally {
                if (c != null) c.disconnect();
            }
        });
    }
}
