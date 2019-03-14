#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "logger/logger.h"

int get_module_base(char *module_name)
{
	FILE *fp;
	long addr = 0;
	char *pch;
	char line[1024];

	fp = fopen("/proc/self/maps", "r");

	if (fp != NULL) 
	{
		while (fgets(line, sizeof(line), fp)) 
		{
			if (strstr(line, module_name)) 
			{
				pch = strtok(line, "-");
				addr = strtoul(pch, NULL, 16);
				break;
			}
		}

		fclose(fp);
	}

	return addr;
}

void get_module_path(char *module_name, char *module_path)
{
	FILE *fp;
	long addr = 0;
	char *pch;
	char line[1024];

	fp = fopen("/proc/self/maps", "r");

	if (fp != NULL) 
	{
		while (fgets(line, sizeof(line), fp)) 
		{
			if (strstr(line, module_name)) 
			{
				char *path = strstr(line, "/");
				path[strlen(path) - 1] = 0x00;
				strcpy(module_path, path);
				break;
			}
		}

		fclose(fp);
	}
}

int advance_dlsym(const char *libname, const char *find_sym_name)
{
	void *buff = NULL;
	char module_path[256] = { 0x00 };
	int module_base = get_module_base((char *)libname);
	get_module_path((char *)libname, module_path);

	int fd = open(module_path, O_RDONLY);
	if (fd == -1)
	{
		return 0;
	}
	
	struct stat stat_data;
	fstat(fd, &stat_data);
	buff = mmap(0, stat_data.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (buff <= 0)
	{
		close(fd);
		return 0;
	}
	
	Elf32_Shdr *sym_table_header = 0;
	Elf32_Shdr *str_table_header = 0;
	Elf32_Ehdr *elf_header = (Elf32_Ehdr *)buff;
	Elf32_Shdr *section_header = (Elf32_Shdr *)((int)buff + elf_header->e_shoff);

	for (int i = 0; i < elf_header->e_shnum; i++)
	{
		if (section_header[i].sh_type == SHT_DYNSYM || section_header[i].sh_type == SHT_SYMTAB)
		{
			sym_table_header = &section_header[i];
			if (sym_table_header->sh_offset > 0)
			{
				int str_table_addr = (int)buff + section_header[sym_table_header->sh_link].sh_offset;
				Elf32_Sym *sym = (Elf32_Sym *)((int)buff + sym_table_header->sh_offset);
				int sym_count = sym_table_header->sh_size / sizeof(Elf32_Sym);
				for (int j = 0; j < sym_count; j++)
				{
					char *sym_name = (char *)(str_table_addr + sym->st_name);
					if (strcmp(sym_name, find_sym_name) == 0)
					{
						int addr = sym->st_value + module_base;
						munmap(buff, stat_data.st_size);
						return addr;
					}
					sym++;
				}
			}
		}
	}

	munmap(buff, stat_data.st_size);
	return 0;
}

int advance_dlsym_fuzzy(const char *libname, const char *find_sym_name)
{
	void *buff = NULL;
	char module_path[256] = { 0x00 };
	int module_base = get_module_base((char *)libname);
	get_module_path((char *)libname, module_path);

	int fd = open(module_path, O_RDONLY);
	if (fd == -1)
	{
		return 0;
	}
	
	struct stat stat_data;
	fstat(fd, &stat_data);
	buff = mmap(0, stat_data.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (buff <= 0)
	{
		close(fd);
		return 0;
	}
	
	Elf32_Shdr *sym_table_header = 0;
	Elf32_Shdr *str_table_header = 0;
	Elf32_Ehdr *elf_header = (Elf32_Ehdr *)buff;
	Elf32_Shdr *section_header = (Elf32_Shdr *)((int)buff + elf_header->e_shoff);

	for (int i = 0; i < elf_header->e_shnum; i++)
	{
		if (section_header[i].sh_type == SHT_DYNSYM || section_header[i].sh_type == SHT_SYMTAB)
		{
			sym_table_header = &section_header[i];
			if (sym_table_header->sh_offset > 0)
			{
				int str_table_addr = (int)buff + section_header[sym_table_header->sh_link].sh_offset;
				Elf32_Sym *sym = (Elf32_Sym *)((int)buff + sym_table_header->sh_offset);
				int sym_count = sym_table_header->sh_size / sizeof(Elf32_Sym);
				for (int j = 0; j < sym_count; j++)
				{
					char *sym_name = (char *)(str_table_addr + sym->st_name);
					if (strstr(sym_name, find_sym_name) != nullptr)
					{
						int addr = sym->st_value + module_base;
						munmap(buff, stat_data.st_size);
						return addr;
					}
					sym++;
				}
			}
		}
	}

	munmap(buff, stat_data.st_size);
	return 0;
}

void cache_flush(int begin, int end)
{   
	static int(*cacheflush)(int, int, int) = nullptr;
	if (cacheflush == nullptr)
	{
		void *plibc = dlopen("libc.so", RTLD_LAZY);
		cacheflush = (int(*)(int, int, int))dlsym(plibc, "cacheflush");
	}
	if (cacheflush != nullptr)
	{
		cacheflush(begin, end, 0);
	}
}