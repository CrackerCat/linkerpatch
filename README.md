# linkerpatch
android N linker patch


android N以后，采用namespace对so加载进行隔离，详细：https://developer.android.com/about/versions/nougat/android-7.0-changes.html#ndk

linker patch提供以下API绕过上述限制：

extern "C" void addHook(const char* src, const char* dst);

extern "C" void delHook(const char* src);

extern "C" void addHijack(const char* src, const char* dst)

extern "C" void delHijack(const char* src)

extern "C" void addTrampoline(const char* srcSo, const char* srcSym, const char* dstSo, const char* dstSym, const char* cond);

extern "C" void delTrampoline(const char* srcSo, const char* srcSym);

extern "C" void initLinkerPatch();

功能说明：

  1、初始化调用initLinkerPatch后，可以突破路径和权限的访问限制（解决dlopen返回null）；
  
  2、addHook：用于替换namespace对dst进行加载（常见使用：动态链接其他namespace的so）；如addHook("libUE4.so", "libxue4.so")， 游戏加载libUE4.so到某个namespace，addhook后再调用dlopen加载libxue4.so时，会使用libUE4.so的namespace进行加载。
  
  3、addHijack:：用于替换so进行加载；
  
  4、addTrampoline：用于替换dlsym函数查找
  
