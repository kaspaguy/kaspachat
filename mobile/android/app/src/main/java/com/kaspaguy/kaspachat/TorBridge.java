package com.kaspaguy.kaspachat;

// The Tor built into the app (tor/, Arti, cross-compiled to libkaspachat_tor.so). start() blocks until Tor is ready and
// returns a SOCKS port on 127.0.0.1 that only reaches the given onion host, or -1 with the reason in error().
final class TorBridge {
    static {
        System.loadLibrary("kaspachat_tor");
    }

    static native int start(String dir, String hosts);

    static native String error();

    private TorBridge() {}
}
