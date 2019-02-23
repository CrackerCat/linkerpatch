LOCAL_PATH			:= $(call my-dir)
############# Substrate ##############
include $(CLEAR_VARS)

LOCAL_MODULE := Substrate
LOCAL_SRC_FILES := Substrate/libSubstrate.a

include $(PREBUILT_STATIC_LIBRARY)
############### linkerpatch ##################
include $(CLEAR_VARS)

LOCAL_MODULE		:= linkerpatch
LOCAL_ARM_MODE		:= arm
LOCAL_CPP_EXTENSION	:= .cpp
LOCAL_C_INCLUDES	:= $(LOCAL_PATH)
LOCAL_LDLIBS		:= -llog -landroid
LOCAL_STATIC_LIBRARIES	+= Substrate
LOCAL_SRC_FILES		:=	main.cpp \
						common\Helper.cpp

include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_STATIC_LIBRARY)
############# install ##############
include $(CLEAR_VARS)

temp_path	:= /data/local/tmp
game_path	:= /data/data/io.virtualapp/lib

all:
	adb push $(NDK_APP_DST_DIR)/liblinkerpatch.so $(temp_path)
	adb shell "su -c 'cp -rf $(temp_path)/liblinkerpatch.so $(game_path)'"
	adb shell "su -c 'chmod 777 $(game_path)/*'"