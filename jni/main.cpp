#include <jni.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex>
#include <vector>
#include <tuple>
#include <sys/mman.h>
#include <sys/stat.h>
#include <logger/logger.h>
#include <common/Helper.h>
#include <Substrate/SubstrateHook.h>

#define PAGE_SIZE 4096
#define PAGE_START(addr) (~(PAGE_SIZE - 1) & (addr))
#define ALIGN(x,a) (((x)+(a)-1)&~(a-1))

static std::vector<std::tuple<std::string, std::string, std::string>> allHook;		// src, dst, cond
static std::vector<std::tuple<std::string, std::string, std::string>> allHijack;	// src, dst, cond

struct CodeSection
{
	uint32_t StartAddr;
	uint32_t EndAddr;
	std::string FilePath;
};

static void refreshMap(std::vector<CodeSection>& sectionMap)
{
	auto fp = fopen("/proc/self/maps", "r");
	if (fp == nullptr)
	{
		return;
	}

	char line[4096] = {0x00};
	while (fgets(line, sizeof(line), fp))
	{
		line[strlen(line)-1] = 0x00;
		static std::regex pattern("^([0-9a-z]+)-([0-9a-z]+)\\s+r[w-]xp.*?(\\/.*)");
		std::smatch matched;
		if (std::regex_match(std::string(line), matched, pattern))
		{
			CodeSection item{};
			item.FilePath = matched[3].str();
			sscanf(matched[1].str().c_str(), "%x", &item.StartAddr);
			sscanf(matched[2].str().c_str(), "%x", &item.EndAddr);
			sectionMap.push_back(item);
		}
	}

	fclose(fp);
}

static CodeSection* findSectionByAddr(uint32_t addr)
{
	std::vector<CodeSection> sectionMap;
	refreshMap(sectionMap);
	for(size_t i = 0; i < sectionMap.size(); i++)
	{
		if (sectionMap[i].StartAddr <= addr && sectionMap[i].EndAddr >= addr)
		{
			return &sectionMap[i];
		}
	}
	
	return nullptr;
}

static CodeSection* findSectionByName(const char* name)
{
	std::vector<CodeSection> sectionMap;
	refreshMap(sectionMap);
	for(size_t i = 0; i < sectionMap.size(); i++)
	{
		if (strstr(sectionMap[i].FilePath.c_str(), name) != nullptr)
		{
			return &sectionMap[i];
		}
	}
	
	return nullptr;
}

static void patchLinker()
{
	int addrAccessible = advance_dlsym("/system/bin/linker", "__dl__ZN19android_namespace_t13is_accessibleERKNSt3__112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE");
	if (addrAccessible > 0)
	{
		if (addrAccessible % 4 != 0)
		{
        	addrAccessible--;
		}

		if (mprotect((void*)PAGE_START(addrAccessible), PAGE_SIZE*2, PROT_EXEC | PROT_WRITE | PROT_READ) == 0)
		{
			*(int*)addrAccessible = 0x47702001;
			cache_flush(addrAccessible, addrAccessible+4);
		}
	}

	int addrGreylisted = advance_dlsym("/system/bin/linker", "__dl__ZL13is_greylistedPKcPK6soinfo");
	if (addrGreylisted == 0)
	{
		if (addrGreylisted % 4 != 0)
		{
        	addrGreylisted--;
		}

		if (mprotect((void*)PAGE_START(addrGreylisted), PAGE_SIZE*2, PROT_EXEC | PROT_WRITE | PROT_READ) == 0)
		{
			*(int*)addrGreylisted = 0x47702001;
			cache_flush(addrGreylisted, addrGreylisted+4);
		}
	}
}

extern "C" void addHook(const char* src, const char* dst, const char* cond)
{
	bool found = false;
	for (auto it = allHook.begin(); it != allHook.end(); it++)
	{
		if (std::get<0>(*it) == src)
		{
			found = true;
			break;
		}
	}
	if (!found)
	{
		LOGD("add hook %s %s %s", src, dst, cond);
		allHook.push_back(std::make_tuple(src, dst, cond));
	}
}

extern "C" void delHook(const char* src)
{
	for (auto it = allHook.begin(); it != allHook.end(); it++)
	{
		if (std::get<0>(*it) == src)
		{
			allHook.erase(it);
			LOGD("del hook %s", src);
			break;
		}
	}
}

extern "C" void addHijack(const char* src, const char* dst, const char* cond)
{
	bool found = false;
	for (auto it = allHijack.begin(); it != allHijack.end(); it++)
	{
		if (std::get<0>(*it) == src)
		{
			found = true;
			break;
		}
	}
	if (!found)
	{
		LOGD("add hijack %s %s %s", src, dst, cond);
		allHijack.push_back(std::make_tuple(src, dst, cond));
	}
}

extern "C" void delHijack(const char* src)
{
	for (auto it = allHijack.begin(); it != allHijack.end(); it++)
	{
		if (std::get<0>(*it) == src)
		{
			allHijack.erase(it);
			LOGD("del hijack %s", src);
			break;
		}
	}
}

static void* (*oldDoOpen)(const char* name, int flags, const void* extinfo, void* caller_addr) = nullptr;
static void* myDoOpen(const char* name, int flags, const void* extinfo, void* caller_addr)
{
	auto callerSection = findSectionByAddr((uint32_t)caller_addr);
	if (callerSection != nullptr)
	{
		LOGD("do_dlopen %s from %s(%p)", name, callerSection->FilePath.c_str(), caller_addr);
	}
	else
	{
		LOGD("do_dlopen %s from %p", name, caller_addr);
	}

	// hijack
	for (auto it = allHijack.begin(); it != allHijack.end(); it++)
	{
		auto src = std::get<0>(*it).c_str();
		auto dst = std::get<1>(*it).c_str();
		auto cond = std::get<2>(*it).c_str();

		if (callerSection != nullptr && !std::regex_match(callerSection->FilePath, std::regex(cond)))
		{
			continue;
		}

		if (strstr(name, src) != nullptr)
		{
			LOGD("hijack: %s->%s", name, dst);
			name = dst;
			break;
		}
	}

	// hook
	for (auto it = allHook.begin(); it != allHook.end(); it++)
	{
		auto src = std::get<0>(*it).c_str();
		auto dst = std::get<1>(*it).c_str();
		auto cond = std::get<2>(*it).c_str();

		if (callerSection != nullptr && !std::regex_match(callerSection->FilePath, std::regex(cond)))
		{
			continue;
		}

		if (strstr(name, src) != nullptr)
		{
			auto section = findSectionByName(dst);
			if (section != nullptr)
			{
				auto newCaller = section->StartAddr + 1;
				LOGD("hook: do_dlopen %s use %s(%x)", name, dst, newCaller);
				return oldDoOpen(name, flags, nullptr, (void*)newCaller);
			}
			else
			{
				LOGD("hook: do_dlopen %s can't use %s", name, dst);
				break;
			}
		}
		else if (strstr(name, dst) != nullptr)
		{
			LOGD("hook: do_dlopen %s then do_dlopen %s", name, src);
			auto ret = oldDoOpen(name, flags, extinfo, caller_addr);
			oldDoOpen(src, flags, extinfo, caller_addr);
			return ret;
		}
	}

	return oldDoOpen(name, flags, extinfo, caller_addr);
}

extern "C" __attribute__((constructor)) void initLinkerPatch()
{
	static bool inited=false;
	if (inited)
	{
		return;
	}
	inited = true;

	LOGD("initLinkerPatch...");

	patchLinker();

	int addrDoOpen = advance_dlsym("/system/bin/linker", "__dl__Z9do_dlopenPKciPK17android_dlextinfoPv");
	if (addrDoOpen != 0)
	{
		MSHookFunction((void*)addrDoOpen, (void*)myDoOpen, (void**)&oldDoOpen);
	}
	else
	{
		LOGD("error: not found do_dlopen!");
	}
}

extern "C" JNIEXPORT void JNICALL Java_io_virtualapp_linker_Patch_addHijack(JNIEnv *env, jclass clazz, jstring src, jstring dst, jstring cond)
{
	addHijack(env->GetStringUTFChars(src, nullptr), env->GetStringUTFChars(dst, nullptr), env->GetStringUTFChars(cond, nullptr));
}

extern "C" JNIEXPORT void JNICALL Java_io_virtualapp_linker_Patch_delHijack(JNIEnv *env, jclass clazz, jstring src)
{
	delHijack(env->GetStringUTFChars(src, nullptr));
}

extern "C" JNIEXPORT void JNICALL Java_io_virtualapp_linker_Patch_addHook(JNIEnv *env, jclass clazz, jstring src, jstring dst, jstring cond)
{
	addHook(env->GetStringUTFChars(src, nullptr), env->GetStringUTFChars(dst, nullptr), env->GetStringUTFChars(cond, nullptr));
}

extern "C" JNIEXPORT void JNICALL Java_io_virtualapp_linker_Patch_delHook(JNIEnv *env, jclass clazz, jstring src)
{
	delHook(env->GetStringUTFChars(src, nullptr));
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *jvm, void *reserved) 
{
	JNIEnv *env = NULL;
	jint result = -1;

	if (jvm->GetEnv((void **)&env, JNI_VERSION_1_4) != JNI_OK) 
	{
		return -1;
	}

	result = JNI_VERSION_1_4;
	initLinkerPatch();
	return result;
}