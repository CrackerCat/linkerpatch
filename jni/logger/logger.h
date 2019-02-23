#pragma once
#include <android/log.h>
#define LOG_TAG "LINKERPATCH"
#define LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
#define LOGDV(fmt, va)  __android_log_vprint(ANDROID_LOG_DEBUG, LOG_TAG, fmt, va)