GO_EASY_ON_ME = 1
DEBUG = 0
FINALPACKAGE = 1

THEOS_PACKAGE_SCHEME = rootless

# THEOS_DEVICE_IP = 10.201.26.179
# THEOS_DEVICE_IP = 172.16.3.21
# THEOS_DEVICE_IP = 192.168.0.33 -p 2222
# THEOS_DEVICE_IP = 172.20.10.4 -p2222
THEOS_DEVICE_IP = 127.0.0.1 -p2222

TARGET := iphone:clang:12.4:12.4
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TOOL_NAME = open1hookiOS15

open1hookiOS15_FILES = main.m
open1hookiOS15_CFLAGS = -fobjc-arc
open1hookiOS15_CODESIGN_FLAGS = -Sentitlements.plist
open1hookiOS15_INSTALL_PATH = /usr/local/bin

include $(THEOS_MAKE_PATH)/tool.mk
