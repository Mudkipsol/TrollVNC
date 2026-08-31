THEOS_PACKAGE_SCHEME = rootless
ARCHS = arm64 arm64e
TARGET = iphone:clang:16.5:15.0
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = PhoneWake
PhoneWake_FILES = Tweak.xm
PhoneWake_CFLAGS = -fobjc-arc -Wall -Wextra
PhoneWake_FRAMEWORKS = Foundation UIKit LocalAuthentication

TOOL_NAME = phonewakectl
phonewakectl_FILES = main.mm
phonewakectl_CFLAGS = -fobjc-arc -Wall -Wextra
phonewakectl_FRAMEWORKS = Foundation
phonewakectl_INSTALL_PATH = /usr/bin

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/tool.mk
