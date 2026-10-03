TARGET = harbour-sailvault

CONFIG += sailfishapp

HEADERS += \
    src/autolock.h \
    src/boottime.h \
    src/clipboardguard.h \
    src/corebridge.h \
    src/databasefile.h \
    src/entrylistmodel.h \
    src/importer.h \
    src/vault.h \
    src/vaulttasks.h

SOURCES += \
    src/autolock.cpp \
    src/clipboardguard.cpp \
    src/databasefile.cpp \
    src/entrylistmodel.cpp \
    src/importer.cpp \
    src/main.cpp \
    src/vault.cpp \
    src/vaulttasks.cpp

INCLUDEPATH += core/include

# The spec passes the package version; the About page shows it.
DEFINES += APP_VERSION=\\\"$$VERSION\\\"

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
rust_core.commands = cd $$PWD && CARGO_HOME=$$OUT_PWD/cargo-home cargo build --release --offline --locked \
    --target $$RUST_TRIPLE \
    --manifest-path $$PWD/core/Cargo.toml --target-dir $$RUST_TARGET_DIR
rust_core.depends = FORCE
QMAKE_EXTRA_TARGETS += rust_core
PRE_TARGETDEPS += $$RUST_STATICLIB

LIBS += $$RUST_STATICLIB -lpthread -ldl -lm

# Full RELRO (read-only GOT after startup) and no symbol table in the
# shipped binary.
QMAKE_LFLAGS += -Wl,-z,relro,-z,now -s

DISTFILES += \
    qml/harbour-sailvault.qml \
    qml/components/PasswordInput.qml \
    qml/cover/CoverPage.qml \
    qml/pages/EntryListPage.qml \
    qml/pages/GroupDialog.qml \
    qml/pages/ImportPage.qml \
    qml/pages/EntryPage.qml \
    qml/pages/EntryDialog.qml \
    qml/pages/HistoryPage.qml \
    qml/pages/MovePage.qml \
    qml/pages/NewDatabaseDialog.qml \
    qml/pages/AboutPage.qml \
    qml/pages/ThirdPartyPage.qml \
    qml/pages/thirdparty.js \
    qml/pages/UnlockPage.qml \
    rpm/harbour-sailvault.spec \
    harbour-sailvault.desktop

SAILFISHAPP_ICONS = 86x86 108x108 128x128 172x172
