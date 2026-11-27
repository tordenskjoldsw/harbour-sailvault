# Tests of the C++ bridge that run on the host, against the host build of the
# Rust core and the real strength estimator. Built and run by
# tools/run-bridge-tests.sh, which passes CORE_LIB.
TEMPLATE = app
TARGET = bridge-tests
QT += core gui testlib
CONFIG += console c++11
CONFIG -= app_bundle

isEmpty(CORE_LIB): error("Run tools/run-bridge-tests.sh; it passes CORE_LIB.")

ROOT = $$PWD/../..
INCLUDEPATH += $$ROOT/src $$ROOT/core/include $$ROOT/third_party/zxcvbn

HEADERS += \
    $$ROOT/src/autolock.h \
    $$ROOT/src/clipboardguard.h \
    $$ROOT/src/databases.h \
    $$ROOT/src/vault.h

SOURCES += \
    $$ROOT/src/autolock.cpp \
    $$ROOT/src/clipboardguard.cpp \
    $$ROOT/src/databasefile.cpp \
    $$ROOT/src/databases.cpp \
    $$ROOT/src/estimator.c \
    $$ROOT/src/vault.cpp \
    $$ROOT/src/vaulttasks.cpp \
    $$ROOT/src/wipedstack.c \
    tst_passwordreport.cpp

LIBS += $$CORE_LIB -lpthread -ldl -lm
