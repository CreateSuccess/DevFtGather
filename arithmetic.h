#ifndef ARITHMETIC_H
#define ARITHMETIC_H

/* SM3算法产生的哈希值大小（单位：字节） */
#define SM3_HASH_SIZE 32 


#define LOG_DATA(d, l)\
do\
{\
	int i;\
	for(i=0;i<l;i++)\
	{\
		if((i+1) % 16) \
			printf("%02X ", d[i]);\
		else\
			printf("%02X\n", d[i]);\
	}\
	if(i % 16) printf("\n");\
}\
while(0)


/* SM3上下文 */
typedef struct SM3Context
{
	unsigned int intermediateHash[SM3_HASH_SIZE / 4];
	unsigned char messageBlock[64];
} SM3Context;

#ifdef __cplusplus
extern "C"
{
#endif

/*******************************************************************************
* Function Name  : QCard_Sm3
* Description    : 获取32位散列值
* Input          : message      : 源数据
*                : messageLen   : 数据长度
* Output         : digest       : 散列值
* Return         : 成功返回0 ;其它返回错误值
*******************************************************************************/
unsigned char *QCard_Sm3(const unsigned char *message,
	unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE]);

unsigned char *QCard_Base64Encry(const unsigned char *buf, const long size, unsigned char *base64Char);
unsigned char *QCard_Base64Decode(const unsigned char *base64Char, const long base64CharSize, unsigned char *originChar, long originCharSize);

int base64_encode(const char *buf, int size, char *base64Char, int *outlen);
int base64_decode(const char *indata, int inlen, char *outdata, int *outlen);


char* StrSHA256(const char* str, long long length, char* sha256, unsigned int *sha256len);


#ifdef __cplusplus
}
#endif

#endif // QCARD_ARITHMETIC_H