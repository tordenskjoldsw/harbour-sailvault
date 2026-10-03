TARGET = harbour-sailvault

CONFIG += sailfishapp

SOURCES += src/main.cpp

INCLUDEPATH += core/include

# Build the Rust core with cargo before linking. CARGO_HOME is isolated so the
# build engine, which shares the host home directory, never reads the host's
# cargo configuration or registry. Cargo runs from the source root so it finds
# .cargo/config.toml with the vendored sources, also in shadow builds.
#
# Inside the build engine, cargo targets the engine's own architecture unless
# the triple is given explicitly.
equals(QT_ARCH, arm64): RUST_TRIPLE = aarch64-unknown-linux-gnu
else:equals(QT_ARCH, arm): RUST_TRIPLE = armv7-unknown-linux-gnueabihf
else:equals(QT_ARCH, i386): RUST_TRIPLE = i686-unknown-linux-gnu
else: error("Unsupported QT_ARCH for the Rust core: $$QT_ARCH")

RUST_TARGET_DIR = $$OUT_PWD/rust-target
RUST_STATICLIB = $$RUST_TARGET_DIR/$$RUST_TRIPLE/release/libsailvault_core.a

rust_core.target = $$RUST_STATICLIB
rust_core.commands = cd $$PWD && CARGO_HOME=$$OUT_PWD/cargo-home cargo build --release --offline \
    --target $$RUST_TRIPLE \
    --manifest-path $$PWD/core/Cargo.toml --target-dir $$RUST_TARGET_DIR
rust_core.depends = FORCE
QMAKE_EXTRA_TARGETS += rust_core
PRE_TARGETDEPS += $$RUST_STATICLIB

LIBS += $$RUST_STATICLIB -lpthread -ldl -lm

DISTFILES += \
    qml/harbour-sailvault.qml \
    qml/cover/CoverPage.qml \
    qml/pages/SpikePage.qml \
    rpm/harbour-sailvault.spec \
    harbour-sailvault.desktop

SAILFISHAPP_ICONS = 86x86 108x108 128x128 172x172
