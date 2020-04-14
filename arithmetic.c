/*************************************************
Copyright (C), 2009 Qasky Co., Ltd
File name: qcard_arithmetic.c
Author: Jianbin Wang    Version:  1.0.0      Date: 2019年7月16日
Description: 用于业务间的算法处理
为使此算法兼容32位、64位下Linux或Windows系统，
选择 int 来表示 32 位整数。
消息长度最大限定为 2**32 - 1（单位：比特），
且为 8 的倍数（消息的最小单元为字节）。
*************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <memory.h>
#include "arithmetic.h"

static void *QCARD_MALLOC(size_t size)
{
	void *ptr = NULL;
	if(!size)
	{
		return NULL;
	}
	ptr = malloc(size);
	if(ptr)
	{
		memset(ptr, 0, size);
	}
	return ptr;
}

#define QCARD_FREE(ptr) \
{\
	if( ptr!= NULL) \
	{\
		free(ptr); \
		ptr =NULL; \
	}\
}

/*
* 判断运行环境是否为小端
*/
static const int endianTest = 1;
#define IsLittleEndian() (*(char *)&endianTest == 1)

/*
* 向左循环移位
*/
#define LeftRotate(word, bits) ( (word) << (bits) | (word) >> (32 - (bits)) )

/*
* 反转四字节整型字节序
*/
unsigned int *ReverseWord(unsigned int *word)
{
    unsigned char *byte, temp;

    byte = (unsigned char *)word;
    temp = byte[0];
    byte[0] = byte[3];
    byte[3] = temp;

    temp = byte[1];
    byte[1] = byte[2];
    byte[2] = temp;
    return word;
}

/*
* T
*/
unsigned int T(int i)
{
    if (i >= 0 && i <= 15)
        return 0x79CC4519;
    else if (i >= 16 && i <= 63)
        return 0x7A879D8A;
    else
        return 0;
}

/*
* FF
*/
unsigned int FF(unsigned int X, unsigned int Y, unsigned int Z, int i)
{
    if (i >= 0 && i <= 15)
        return X ^ Y ^ Z;
    else if (i >= 16 && i <= 63)
        return (X & Y) | (X & Z) | (Y & Z);
    else
        return 0;
}

/*
* GG
*/
unsigned int GG(unsigned int X, unsigned int Y, unsigned int Z, int i)
{
    if (i >= 0 && i <= 15)
        return X ^ Y ^ Z;
    else if (i >= 16 && i <= 63)
        return (X & Y) | (~X & Z);
    else
        return 0;
}

/*
* P0
*/
unsigned int P0(unsigned int X)
{
    return X ^ LeftRotate(X, 9) ^ LeftRotate(X, 17);
}

/*
* P1
*/
unsigned int P1(unsigned int X)
{
    return X ^ LeftRotate(X, 15) ^ LeftRotate(X, 23);
}

/*
* 初始化函数
*/
void SM3Init(SM3Context *context)
{
    context->intermediateHash[0] = 0x7380166F;
    context->intermediateHash[1] = 0x4914B2B9;
    context->intermediateHash[2] = 0x172442D7;
    context->intermediateHash[3] = 0xDA8A0600;
    context->intermediateHash[4] = 0xA96F30BC;
    context->intermediateHash[5] = 0x163138AA;
    context->intermediateHash[6] = 0xE38DEE4D;
    context->intermediateHash[7] = 0xB0FB0E4E;
}

/*
* 处理消息块
*/
void SM3ProcessMessageBlock(SM3Context *context)
{
    int i;
    unsigned int W[68];
    unsigned int W_[64];
    unsigned int A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2;

    /* 消息扩展 */
    for (i = 0; i < 16; i++)
    {
        W[i] = *(unsigned int *)(context->messageBlock + i * 4);
        if (IsLittleEndian())
            ReverseWord(W + i);
        //printf("%d: %x\n", i, W[i]);    
    }
    for (i = 16; i < 68; i++)
    {
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ LeftRotate(W[i - 3], 15))
            ^ LeftRotate(W[i - 13], 7)
            ^ W[i - 6];
        //printf("%d: %x\n", i, W[i]);    
    }
    for (i = 0; i < 64; i++)
    {
        W_[i] = W[i] ^ W[i + 4];
        //printf("%d: %x\n", i, W_[i]);    
    }

    /* 消息压缩 */
    A = context->intermediateHash[0];
    B = context->intermediateHash[1];
    C = context->intermediateHash[2];
    D = context->intermediateHash[3];
    E = context->intermediateHash[4];
    F = context->intermediateHash[5];
    G = context->intermediateHash[6];
    H = context->intermediateHash[7];
    for (i = 0; i < 64; i++)
    {
        SS1 = LeftRotate((LeftRotate(A, 12) + E + LeftRotate(T(i), i)), 7);
        SS2 = SS1 ^ LeftRotate(A, 12);
        TT1 = FF(A, B, C, i) + D + SS2 + W_[i];
        TT2 = GG(E, F, G, i) + H + SS1 + W[i];
        D = C;
        C = LeftRotate(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = LeftRotate(F, 19);
        F = E;
        E = P0(TT2);
    }
    context->intermediateHash[0] ^= A;
    context->intermediateHash[1] ^= B;
    context->intermediateHash[2] ^= C;
    context->intermediateHash[3] ^= D;
    context->intermediateHash[4] ^= E;
    context->intermediateHash[5] ^= F;
    context->intermediateHash[6] ^= G;
    context->intermediateHash[7] ^= H;
}

/*******************************************************************************
* Function Name  : QCard_Sm3
* Description    : 获取32位散列值
* Input          : message      : 源数据
*                : messageLen   : 数据长度
* Output         : digest       : 散列值
* Return         : 成功返回0 ;其它返回错误值
*******************************************************************************/
unsigned char *QCard_Sm3(const unsigned char *message,
                         unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE])
{
    SM3Context context;
    unsigned int i, remainder, bitLen;

    /* 初始化上下文 */
    SM3Init(&context);

    /* 对前面的消息分组进行处理 */
    for (i = 0; i < messageLen / 64; i++)
    {
        memcpy(context.messageBlock, message + i * 64, 64);
        SM3ProcessMessageBlock(&context);
    }

    /* 填充消息分组，并处理 */
    bitLen = messageLen * 8;
    if (IsLittleEndian())
        ReverseWord(&bitLen);
    remainder = messageLen % 64;
    memcpy(context.messageBlock, message + i * 64, remainder);
    context.messageBlock[remainder] = 0x80;
    if (remainder <= 55)
    {
        /* 长度按照大端法占8个字节，该程序只考虑长度在 2**32 - 1（单位：比特）以内的情况，
        * 故将高 4 个字节赋为 0 。*/
        memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1 - 8 + 4);
        memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
        SM3ProcessMessageBlock(&context);
    }
    else
    {
        memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1);
        SM3ProcessMessageBlock(&context);
        /* 长度按照大端法占8个字节，该程序只考虑长度在 2**32 - 1（单位：比特）以内的情况，
        * 故将高 4 个字节赋为 0 。*/
        memset(context.messageBlock, 0, 64 - 4);
        memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
        SM3ProcessMessageBlock(&context);
    }

    /* 返回结果 */
    if (IsLittleEndian())
        for (i = 0; i < 8; i++)
            ReverseWord(context.intermediateHash + i);
    memcpy(digest, context.intermediateHash, SM3_HASH_SIZE);

    return digest;
}

static const char *ALPHA_BASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

unsigned char *QCard_Base64Encry(const unsigned char *buf, const long size, unsigned char *base64Char)
{
    int a = 0;
    int i = 0;
    while (i < size) {
        char b0 = buf[i++];
        char b1 = (i < size) ? buf[i++] : 0;
        char b2 = (i < size) ? buf[i++] : 0;

        int int63 = 0x3F; //  00111111
        int int255 = 0xFF; // 11111111
        base64Char[a++] = ALPHA_BASE[(b0 >> 2) & int63];
        base64Char[a++] = ALPHA_BASE[((b0 << 4) | ((b1 & int255) >> 4)) & int63];
        base64Char[a++] = ALPHA_BASE[((b1 << 2) | ((b2 & int255) >> 6)) & int63];
        base64Char[a++] = ALPHA_BASE[b2 & int63];
    }
    switch (size % 3) {
    case 1:
        base64Char[--a] = '=';
    case 2:
        base64Char[--a] = '=';
    }
    return base64Char;
}
unsigned char *QCard_Base64Decode(const unsigned char *base64Char, const long base64CharSize, unsigned char *originChar, long originCharSize)
{
    int toInt[128] = { -1 };
    int i = 0;
    int int255 = 0xFF;
    int index = 0;
    for (i = 0; i < 64; i++) {
        toInt[ALPHA_BASE[i]] = i;
    }
    for (i = 0; i < base64CharSize; i += 4) {
        int c0 = toInt[base64Char[i]];
        int c1 = toInt[base64Char[i + 1]];
        int c2 = toInt[base64Char[i + 2]];
        int c3 = toInt[base64Char[i + 3]];
        originChar[index++] = (((c0 << 2) | (c1 >> 4)) & int255);
        if (index >= originCharSize) {
            return originChar;
        }

        originChar[index++] = (((c1 << 4) | (c2 >> 2)) & int255);
        if (index >= originCharSize) {
            return originChar;
        }
        originChar[index++] = (((c2 << 6) | c3) & int255);
    }
    return originChar;
}

// base64 转换表, 共64个
static const char base64_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '+', '/'};

// 解码时使用
static const unsigned char base64_suffix_map[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 255,
    255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 253, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,
    255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,
    7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,
    19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,
    37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
    49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255 };

static char cmove_bits(unsigned char src, unsigned lnum, unsigned rnum) {
    src <<= lnum; // src = src << lnum;
    src >>= rnum; // src = src >> rnum;
    return src;
}

static const char *ALPHA_BASE2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_encode(const char *buf, int size, char *base64Char, int *outlen)
{
    int a = 0;
    int i = 0;
    while (i < size) {
        char b0 = buf[i++];
        char b1 = (i < size) ? buf[i++] : 0;
        char b2 = (i < size) ? buf[i++] : 0;

        int int63 = 0x3F; //  00111111
        int int255 = 0xFF; // 11111111
        base64Char[a++] = ALPHA_BASE2[(b0 >> 2) & int63];
        base64Char[a++] = ALPHA_BASE2[((b0 << 4) | ((b1 & int255) >> 4)) & int63];
        base64Char[a++] = ALPHA_BASE2[((b1 << 2) | ((b2 & int255) >> 6)) & int63];
        base64Char[a++] = ALPHA_BASE2[b2 & int63];
    }
    switch (size % 3) {
    case 1:
        base64Char[--a] = '=';
    case 2:
        base64Char[--a] = '=';
    }
    *outlen = strlen(base64Char);
    return 0;
}

int base64_decode(const char *indata, int inlen, char *outdata, int *outlen) {

    int ret = 0;
    int t = 0, x = 0, y = 0, i = 0;
    unsigned char c = 0;
    int g = 3;

    if (indata == NULL || inlen <= 0 || outdata == NULL || outlen == NULL) {
        return ret = -1;
    }
    if (inlen % 4 != 0) { // 需要解码的数据不是4字节倍数
        return ret = -2;
    }

    while (indata[x] != 0) {
        // 需要解码的数据对应的ASCII值对应base64_suffix_map的值
        c = base64_suffix_map[indata[x++]];
        if (c == 255) return -1;// 对应的值不在转码表中
        if (c == 253) continue;// 对应的值是换行或者回车
        if (c == 254) { c = 0; g--; }// 对应的值是'='
        t = (t<<6) | c; // 将其依次放入一个int型中占3字节
        if (++y == 4) {
            outdata[i++] = (unsigned char)((t>>16)&0xff);
            if (g > 1) outdata[i++] = (unsigned char)((t>>8)&0xff);
            if (g > 2) outdata[i++] = (unsigned char)(t&0xff);
            y = t = 0;
        }
    }
    if (outlen != NULL) {
        *outlen = i;
    }
    return ret;
}

#define SHA256_ROTL(a,b) (((a>>(32-b))&(0x7fffffff>>(31-b)))|(a<<b))
#define SHA256_SR(a,b) ((a>>b)&(0x7fffffff>>(b-1)))
#define SHA256_Ch(x,y,z) ((x&y)^((~x)&z))
#define SHA256_Maj(x,y,z) ((x&y)^(x&z)^(y&z))
#define SHA256_E0(x) (SHA256_ROTL(x,30)^SHA256_ROTL(x,19)^SHA256_ROTL(x,10))
#define SHA256_E1(x) (SHA256_ROTL(x,26)^SHA256_ROTL(x,21)^SHA256_ROTL(x,7))
#define SHA256_O0(x) (SHA256_ROTL(x,25)^SHA256_ROTL(x,14)^SHA256_SR(x,3))
#define SHA256_O1(x) (SHA256_ROTL(x,15)^SHA256_ROTL(x,13)^SHA256_SR(x,10))

void SHA16TO2(char *x, long y, int i)
{
    char z[4] = {0};
    memcpy(z, &y, 4);
    x[0] = z[3];
    x[1] = z[2];
    x[2] = z[1];
    x[3] = z[0];
}

extern char* StrSHA256(const char* str, long long length, char * sha256, unsigned int *sha256Len){
    /*
    计算字符串SHA-256
    参数说明：
    str         字符串指针
    length      字符串长度
    sha256         用于保存SHA-256的字符串指针
    返回值为参数sha256
    */
    char *pp, *ppend;
    long l, i, W[64], T1, T2, A, B, C, D, E, F, G, H, H0, H1, H2, H3, H4, H5, H6, H7;
    long K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };
    H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
    H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;
    l = length + ((length % 64 >= 56) ? (128 - length % 64) : (64 - length % 64));
    if (!(pp = (char*)QCARD_MALLOC((unsigned long)l))) return 0;
    for (i = 0; i < length; pp[i + 3 - 2 * (i % 4)] = str[i], i++);
    for (pp[i + 3 - 2 * (i % 4)] = 128, i++; i < l; pp[i + 3 - 2 * (i % 4)] = 0, i++);
    *((long*)(pp + l - 4)) = length << 3;
    *((long*)(pp + l - 8)) = length >> 29;
    for (ppend = pp + l; pp < ppend; pp += 64){
        for (i = 0; i < 16; W[i] = ((long*)pp)[i], i++);
        for (i = 16; i < 64; W[i] = (SHA256_O1(W[i - 2]) + W[i - 7] + SHA256_O0(W[i - 15]) + W[i - 16]), i++);
        A = H0, B = H1, C = H2, D = H3, E = H4, F = H5, G = H6, H = H7;
        for (i = 0; i < 64; i++){
            T1 = H + SHA256_E1(E) + SHA256_Ch(E, F, G) + K[i] + W[i];
            T2 = SHA256_E0(A) + SHA256_Maj(A, B, C);
            H = G, G = F, F = E, E = D + T1, D = C, C = B, B = A, A = T1 + T2;
        }
        H0 += A, H1 += B, H2 += C, H3 += D, H4 += E, H5 += F, H6 += G, H7 += H;
    }
    free(pp - l);
    if(0)
    {
        sprintf(sha256, "%08X%08X%08X%08X%08X%08X%08X%08X", H0, H1, H2, H3, H4, H5, H6, H7);
        *sha256Len = 64;
    }
    else
    {
        printf("%08X%08X%08X%08X%08X%08X%08X%08X\n", H0, H1, H2, H3, H4, H5, H6, H7);
        SHA16TO2(sha256, H0, 4);

        SHA16TO2(sha256, H0, 4);
        SHA16TO2(sha256+4, H1, 4);
        SHA16TO2(sha256+8, H2, 4);
        SHA16TO2(sha256+12, H3, 4);
        SHA16TO2(sha256+16, H4, 4);
        SHA16TO2(sha256+20, H5, 4);
        SHA16TO2(sha256+24, H6, 4);
        SHA16TO2(sha256+28, H7, 4);
        *sha256Len = 32;
    }
    return sha256;
}