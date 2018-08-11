#include "HashMachine.h"
#include <conio.h>
#include <stdio.h>
#include "common.h"
#include <map>

char usage[] = "USAGE: calc_hash -h (hash_type) [-f (file_name)|-t (text)] \n";

std::list<std::tstring> hash_types = {	"HASH_MD4", "HASH_MD5", "HASH_SHA1", 
										"HASH_SHA224", "HASH_SHA256", "HASH_SHA384", "HASH_SHA512"};
std::map<std::tstring, HASH_TYPE> hash_to_int { 
											{"HASH_MD4", HASH_MD4}, {"HASH_MD5", HASH_MD5},
											{"HASH_SHA1", HASH_SHA1}, {"HASH_SHA224", HASH_SHA224},
											{"HASH_SHA256", HASH_SHA256}, {"HASH_SHA384", HASH_SHA384},
											{"HASH_SHA512", HASH_SHA512}
											};

int main(int, char**)
{
	CmdLine cmd_line;
	cmd_line.AddOption("-f", true, "calc hash of file");
	cmd_line.AddOption("-t", true, "calc hash of text");
	cmd_line.AddOption("-h", true, "type of hash. Supported: HASH_MD4, HASH_MD5, HASH_SHA1, HASH_SHA224, HASH_SHA256, HASH_SHA384, HASH_SHA512", hash_types);
	cmd_line.SetCmd(GetCommandLine());
	if (!cmd_line)
	{
		printf("Incorrect usage.\n%s", usage);
		cmd_line.ShowUsage();
		_getch();
		return 1;
	}
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	/* ... Do some crypto stuff here ... */

	if (cmd_line.IsSet("-f"))
	{
		printf("File hash: %s\n", CalcFileHash(cmd_line.GetString("-f"), hash_to_int[cmd_line.GetString("-h")]).c_str());
	}
	if (cmd_line.IsSet("-t"))
	{
		printf("Text hash: %s\n", CalcTextHash(cmd_line.GetString("-t"), hash_to_int[cmd_line.GetString("-h")]).c_str());
	}
	/*unsigned char asd[10];
	printf("Text hash: %s\n", CalcTextHash("Lol chto eto takoe").c_str());
	printf("File hash: %s\n", CalcFileHash("C:\\Program Files\\OpenSSL\\bin\\openssl.exe").c_str());
	printf("Data hash: %s\n", CalcDataHash(asd, 10).c_str());*/

	/* Clean up */
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();

	printf("Press any key...");
	_getch();
	return 0;
}