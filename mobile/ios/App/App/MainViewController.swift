import Capacitor

// Registers the app's own plugin with the Capacitor bridge (Main.storyboard uses this class).
class MainViewController: CAPBridgeViewController {
    override open func capacitorDidLoad() {
        bridge?.registerPluginInstance(KaspaChatNativePlugin())
    }
}
