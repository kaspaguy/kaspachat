# Release hashes

`android-0.5.7-unsigned.SHA256SUMS` lists the SHA-256 of every file inside the unsigned Android release APK (the APK signature in `META-INF/` is left out because it depends on the signing key) and, on the last line, of the unsigned APK itself.

To check: `tools/build-android.sh <empty dir>` on a machine with JDK 21, the Android SDK, NDK 30.0.16248370, Rust with the Android targets and cargo-ndk, and the Node major used by `tools/build-web.sh`. Two builds from the same source at the same path gave byte-identical output (2026-10-26). The build path affects the native libraries, so build from a clean checkout in the same directory layout.
