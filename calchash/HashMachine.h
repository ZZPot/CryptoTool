#pragma once
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <windows.h>
#include <string>


enum DATA_TYPE
{
	DATA_NONE = -1,
	DATA_TEXT = 0,
	DATA_POINTER = 1,
	DATA_FILE = 2,
	DATA_MAX
};

class DataFile
{
public:
	DataFile(std::string file_name = "");
	virtual ~DataFile();
	DataFile& Init(std::string file_name);
	const unsigned char* GetFilePointer();
	DWORD GetFileSize();
	operator bool();
protected:
	HANDLE _file;
	HANDLE _mapping;
	const unsigned char* _mapped_file;
	DWORD _size;
	bool _mapped;
private:
	void _init(std::string file_name);
	//do all cleanup work
	void _release();
	DataFile(const DataFile&) = delete;
};

struct data_obj
{
	data_obj();
//DATA_TYPE can be DATA_TEXT or DATA_FILE
	data_obj(DATA_TYPE, std::string);
//type become DATA_POINTER
	data_obj(const unsigned char*, size_t);
	virtual ~data_obj();
	DATA_TYPE type;
	std::string string_data;
	const unsigned char* data_pointer;
	size_t data_size;
	DataFile file;
private:
	void _init();
};

enum HASH_TYPE
{
	HASH_NONE = 0,
	HASH_MD4 = 1,
	HASH_MD5,
	HASH_SHA1,
	HASH_SHA224,
	HASH_SHA256,
	HASH_SHA384,
	HASH_SHA512,
	HASH_MAX
};

struct hash_obj
{
	hash_obj(HASH_TYPE t = HASH_NONE);
	virtual ~hash_obj();
	HASH_TYPE type;
	bool hash_exist;
	unsigned char* hash;
	unsigned int hash_size;
	std::string hash_base64;
private:
	void _init();
};

//Calculate hash of provided data
hash_obj* CalcHash(data_obj& data, HASH_TYPE hash_type = HASH_MD5);

/*
class HashMachine
{
public:
	HashMachine();
	virtual ~HashMachine();
	hash_obj CalcHash(data_obj& data, HASH_TYPE hash_type = HASH_MD5);
protected:
	??????
};*/
std::string ToHEX(unsigned char* data, unsigned int size);

//wrappers
std::string CalcFileHash(std::string str, HASH_TYPE type = HASH_MD5);
std::string CalcDataHash(unsigned char* pointer, size_t size, HASH_TYPE type = HASH_MD5);
std::string CalcTextHash(std::string str, HASH_TYPE type = HASH_MD5);