TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
        arp.cpp \
        arphdr.cpp \
        ethhdr.cpp \
        get_attackerinfo.cpp \
        ip.cpp \
        mac.cpp \
        main.cpp

HEADERS += \
    arp.h \
    arphdr.h \
    ethhdr.h \
    get_attackerinfo.h \
    ip.h \
    mac.h
