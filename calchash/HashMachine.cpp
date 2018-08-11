#include "HashMachine.h"
#include "common.h"

//DataFile
DataFile::DataFile(std::string file_name)
{
	_init(file_name);
}
DataFile::~DataFile()
{
	_release();
}
DataFile& DataFile::Init(std::string file_name)
{
	_release();
	_init(file_name);
	return *this;
}
const unsigned char* DataFile::GetFilePointer()
{
	return _mapped_file;
}
DWORD DataFile::GetFileSize()
{
	return _size;
}
DataFile::operator bool()
{
	return _mapped;
}
void DataFile::_init(std::string file_name)
{
	_file = INVALID_HANDLE_VALUE;
	_mapping = NULL;
	_mapped_file = nullptr;
	_mapped = false;
	_size = 0;
	_file = CreateFile(file_name.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
	if (_file == INVALID_HANDLE_VALUE)
		return _release();
	_mapping = CreateFileMapping(_file, 0, PAGE_READONLY, 0, 0, NULL);
	if(_mapping == NULL)
		return _release();
	_mapped_file = (unsigned char*)MapViewOfFile(_mapping, FILE_MAP_READ, 0, 0, 0);
	if(!_mapped_file)
		return _release();
	_mapped = true;
	_size = ::GetFileSize(_file, NULL);
}
void DataFile::_release()
{
	if (_mapped_file)
		UnmapViewOfFile(_mapped_file);
	if (_mapping != NULL)
		CloseHandle(_mapping);
	if (_file != INVALID_HANDLE_VALUE)
		CloseHandle(_file);
	_mapped = false;	
}

//data_obj
data_obj::data_obj()
{
	_init();
}
data_obj::~data_obj()
{

}
data_obj::data_obj(DATA_TYPE t, std::string s)
{
	_init();
	if (t != DATA_TEXT && t != DATA_FILE)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return;
	}
	if (t == DATA_TEXT)
	{
		if (!s.length())
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			return;
		}
		string_data = s;
		type = t;
	}
	if (t == DATA_FILE)
	{
		file.Init(s); // код ошибки установят WINAPI функции
		if (!file)
		{
			_init();
			return;
		}
		type = t;
	}
}
data_obj::data_obj(const unsigned char* d, size_t s)
{
	_init();
	if (d == nullptr)
	{
		SetLastError(ERROR_INVALID_ADDRESS);
		return;
	}
	if (!s)
	{
		SetLastError(ERROR_INCORRECT_SIZE);
		return;
	}
	type = DATA_POINTER;
	data_pointer = d;
	data_size = s;
}
void data_obj::_init()
{
	type = DATA_NONE;
	string_data = "";
	data_pointer = nullptr;
	data_size = 0;
}

//hash_obj
hash_obj::hash_obj(HASH_TYPE t)
{
	_init();
	type = t;
}
hash_obj::~hash_obj()
{
	if (hash_exist)
		OPENSSL_free(hash);
}
void hash_obj::_init()
{
	type = HASH_NONE;
	hash_exist = false;
	hash = nullptr;
	hash_size = 0;
	hash_base64 = "";
}

//No error handling, ha-ha
hash_obj* CalcHash(data_obj& data, HASH_TYPE hash_type)
{
	hash_obj* res = new hash_obj;
	if (hash_type == HASH_NONE || data.type == DATA_NONE)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return res;
	}
	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_create();
	switch (hash_type)
	{
	case HASH_MD4:
		EVP_DigestInit_ex(mdctx, EVP_md4(), NULL);
		res->hash = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_md4()));
		break;
	case HASH_MD5:
		EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
		res->hash = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_md5()));
		break;
	case HASH_SHA1:
		EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
		res->hash = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_sha1()));
		break;
	case HASH_SHA224:
		EVP_DigestInit_ex(mdctx, EVP_sha224(), NULL);
		res->hash = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_sha224()));
		break;
	case HASH_SHA256:
		EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
		res->hash = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
		break;
	case HASH_SHA384:
		EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL);
		res->hash = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_sha384()));
		break;
	case HASH_SHA512:
		EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
		res->hash = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_sha512()));
		break;
	}
	switch (data.type)
	{
	case DATA_TEXT:
		EVP_DigestUpdate(mdctx, data.string_data.c_str(), data.string_data.length());
		break;
	case DATA_POINTER:
		EVP_DigestUpdate(mdctx, data.data_pointer, data.data_size);
		break;
	case DATA_FILE:
		EVP_DigestUpdate(mdctx, data.file.GetFilePointer(), data.file.GetFileSize());
		break;
	}
	if (EVP_DigestFinal_ex(mdctx, res->hash, &res->hash_size))
	{
		res->hash_base64 = ToHEX(res->hash, res->hash_size);
		res->hash_exist = true;
		res->type = hash_type;
	}
	EVP_MD_CTX_destroy(mdctx);
	return res;
}

std::string ToHEX(unsigned char* data, unsigned int size)
{
	std::string res;
	if (data == nullptr)
		return res;
	for (unsigned i = 0; i < size; i++)
	{
		DWORD bWritten = 0;
		char buf[3];
		sprintf_s(buf, 3, "%02X", data[i]);
		res += buf;
	}
	return res;
}

std::string CalcFileHash(std::string str, HASH_TYPE type)
{
	std::string res;
	data_obj data(DATA_FILE, str);
	hash_obj* hash = CalcHash(data, type);
	res = hash->hash_base64;
	delete hash;
	return res;
}
std::string CalcDataHash(unsigned char* pointer, size_t size, HASH_TYPE type)
{
	std::string res;
	data_obj data(pointer, size);
	hash_obj* hash = CalcHash(data, type);
	res = hash->hash_base64;
	delete hash;
	return res;
}
std::string CalcTextHash(std::string str, HASH_TYPE type)
{
	std::string res;
	data_obj data(DATA_TEXT, str);
	hash_obj* hash = CalcHash(data, type);
	res = hash->hash_base64;
	delete hash;
	return res;
}