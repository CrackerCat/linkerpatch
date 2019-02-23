#pragma once

int get_module_base(char *module_name);
void get_module_path(char *module_name, char *module_path);
int advance_dlsym(const char *libname, const char *find_sym_name);
void cache_flush(int begin, int end);