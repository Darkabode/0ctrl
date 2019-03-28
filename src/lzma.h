#ifndef __SHARED_LZMA_H_
#define __SHARED_LZMA_H_

#define SZ_OK 0

#define SZ_ERROR_DATA 1
#define SZ_ERROR_MEM 2
#define SZ_ERROR_CRC 3
#define SZ_ERROR_UNSUPPORTED 4
#define SZ_ERROR_PARAM 5
#define SZ_ERROR_INPUT_EOF 6
#define SZ_ERROR_OUTPUT_EOF 7
#define SZ_ERROR_READ 8
#define SZ_ERROR_WRITE 9
#define SZ_ERROR_PROGRESS 10
#define SZ_ERROR_FAIL 11
#define SZ_ERROR_THREAD 12

#define SZ_ERROR_ARCHIVE 16
#define SZ_ERROR_NO_ARCHIVE 17

typedef int SRes;


/* _LZMA_PROB32 can increase the speed on some CPUs,
but memory usage for CLzmaDec::probs will be doubled in that case */

#ifdef _LZMA_PROB32
#define CLzmaProb Poco::UInt32
#else
#define CLzmaProb Poco::UInt16
#endif


/* ---------- LZMA Properties ---------- */

#define LZMA_PROPS_SIZE 5

typedef struct _CLzmaProps
{
	unsigned lc, lp, pb;
	Poco::UInt32 dicSize;
} CLzmaProps;

/* LzmaProps_Decode - decodes properties
Returns:
SZ_OK
SZ_ERROR_UNSUPPORTED - Unsupported properties
*/

SRes LzmaProps_Decode(CLzmaProps *p, const Poco::UInt8 *data, unsigned size);


/* ---------- LZMA Decoder state ---------- */

/* LZMA_REQUIRED_INPUT_MAX = number of required input Poco::UInt8s for worst case.
Num bits = log2((2^11 / 31) ^ 22) + 26 < 134 + 26 = 160; */

#define LZMA_REQUIRED_INPUT_MAX 20

typedef struct
{
	CLzmaProps prop;
	CLzmaProb *probs;
	Poco::UInt8 *dic;
	const Poco::UInt8 *buf;
	Poco::UInt32 range, code;
	std::size_t dicPos;
	std::size_t dicBufSize;
	Poco::UInt32 processedPos;
	Poco::UInt32 checkDicSize;
	unsigned state;
	Poco::UInt32 reps[4];
	unsigned remainLen;
	int needFlush;
	int needInitState;
	Poco::UInt32 numProbs;
	unsigned tempBufSize;
	Poco::UInt8 tempBuf[LZMA_REQUIRED_INPUT_MAX];
} CLzmaDec;

#define LzmaDec_Construct(p) { (p)->dic = 0; (p)->probs = 0; }

void LzmaDec_Init(CLzmaDec *p);

/* There are two types of LZMA streams:
0) Stream with end mark. That end mark adds about 6 Poco::UInt8s to compressed size.
1) Stream without end mark. You must know exact uncompressed size to decompress such stream. */

typedef enum
{
	LZMA_FINISH_ANY,   /* finish at any point */
	LZMA_FINISH_END    /* block must be finished at the end */
} ELzmaFinishMode;

/* ELzmaFinishMode has meaning only if the decoding reaches output limit !!!

You must use LZMA_FINISH_END, when you know that current output buffer
covers last Poco::UInt8s of block. In other cases you must use LZMA_FINISH_ANY.

If LZMA decoder sees end marker before reaching output limit, it returns SZ_OK,
and output value of destLen will be less than output buffer size limit.
You can check status result also.

You can use multiple checks to test data integrity after full decompression:
1) Check Result and "status" variable.
2) Check that output(destLen) = uncompressedSize, if you know real uncompressedSize.
3) Check that output(srcLen) = compressedSize, if you know real compressedSize.
You must use correct finish mode in that case. */

typedef enum
{
	LZMA_STATUS_NOT_SPECIFIED,               /* use main error code instead */
	LZMA_STATUS_FINISHED_WITH_MARK,          /* stream was finished with end mark. */
	LZMA_STATUS_NOT_FINISHED,                /* stream was not finished */
	LZMA_STATUS_NEEDS_MORE_INPUT,            /* you must provide more input Poco::UInt8s */
	LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK  /* there is probability that stream was finished without end mark */
} ELzmaStatus;

/* ELzmaStatus is used only as output value for function call */


/* ---------- Interfaces ---------- */

/* There are 3 levels of interfaces:
1) Dictionary Interface
2) Buffer Interface
3) One Call Interface
You can select any of these interfaces, but don't mix functions from different
groups for same object. */


/* There are two variants to allocate state for Dictionary Interface:
1) LzmaDec_Allocate / LzmaDec_Free
2) LzmaDec_AllocateProbs / LzmaDec_FreeProbs
You can use variant 2, if you set dictionary buffer manually.
For Buffer Interface you must always use variant 1.

LzmaDec_Allocate* can return:
SZ_OK
SZ_ERROR_MEM         - Memory allocation error
SZ_ERROR_UNSUPPORTED - Unsupported properties
*/

SRes LzmaDec_AllocateProbs(CLzmaDec *p, const Poco::UInt8 *props, unsigned propsSize);
void LzmaDec_FreeProbs(CLzmaDec *p);

SRes LzmaDec_Allocate(CLzmaDec *state, const Poco::UInt8 *prop, unsigned propsSize);
void LzmaDec_Free(CLzmaDec *state);

/* ---------- Dictionary Interface ---------- */

/* You can use it, if you want to eliminate the overhead for data copying from
dictionary to some other external buffer.
You must work with CLzmaDec variables directly in this interface.

STEPS:
LzmaDec_Constr()
LzmaDec_Allocate()
for (each new stream)
{
LzmaDec_Init()
while (it needs more decompression)
{
LzmaDec_DecodeToDic()
use data from CLzmaDec::dic and update CLzmaDec::dicPos
}
}
LzmaDec_Free()
*/

/* LzmaDec_DecodeToDic

The decoding to internal dictionary buffer (CLzmaDec::dic).
You must manually update CLzmaDec::dicPos, if it reaches CLzmaDec::dicBufSize !!!

finishMode:
It has meaning only if the decoding reaches output limit (dicLimit).
LZMA_FINISH_ANY - Decode just dicLimit Poco::UInt8s.
LZMA_FINISH_END - Stream must be finished after dicLimit.

Returns:
SZ_OK
status:
LZMA_STATUS_FINISHED_WITH_MARK
LZMA_STATUS_NOT_FINISHED
LZMA_STATUS_NEEDS_MORE_INPUT
LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK
SZ_ERROR_DATA - Data error
*/

SRes LzmaDec_DecodeToDic(CLzmaDec *p, std::size_t dicLimit, const Poco::UInt8 *src, std::size_t *srcLen, ELzmaFinishMode finishMode, ELzmaStatus *status);


/* ---------- Buffer Interface ---------- */

/* It's zlib-like interface.
See LzmaDec_DecodeToDic description for information about STEPS and return results,
but you must use LzmaDec_DecodeToBuf instead of LzmaDec_DecodeToDic and you don't need
to work with CLzmaDec variables manually.

finishMode:
It has meaning only if the decoding reaches output limit (*destLen).
LZMA_FINISH_ANY - Decode just destLen Poco::UInt8s.
LZMA_FINISH_END - Stream must be finished after (*destLen).
*/

SRes LzmaDec_DecodeToBuf(CLzmaDec *p, Poco::UInt8 *dest, std::size_t *destLen, const Poco::UInt8 *src, std::size_t *srcLen, ELzmaFinishMode finishMode, ELzmaStatus *status);


/* ---------- One Call Interface ---------- */

/* LzmaDecode

finishMode:
It has meaning only if the decoding reaches output limit (*destLen).
LZMA_FINISH_ANY - Decode just destLen Poco::UInt8s.
LZMA_FINISH_END - Stream must be finished after (*destLen).

Returns:
SZ_OK
status:
LZMA_STATUS_FINISHED_WITH_MARK
LZMA_STATUS_NOT_FINISHED
LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK
SZ_ERROR_DATA - Data error
SZ_ERROR_MEM  - Memory allocation error
SZ_ERROR_UNSUPPORTED - Unsupported properties
SZ_ERROR_INPUT_EOF - It needs more Poco::UInt8s in input buffer (src).
*/

SRes LzmaDecode(Poco::UInt8 *dest, std::size_t *destLen, const Poco::UInt8 *src, std::size_t *srcLen, const Poco::UInt8 *propData, unsigned propSize, ELzmaFinishMode finishMode, ELzmaStatus *status);












#define LZMA_PROPS_SIZE 5

typedef struct _CLzmaEncProps
{
	int level;       /*  0 <= level <= 9 */
	Poco::UInt32 dictSize; /* (1 << 12) <= dictSize <= (1 << 27) for 32-bit version
					 (1 << 12) <= dictSize <= (1 << 30) for 64-bit version
					 default = (1 << 24) */
	Poco::UInt64 reduceSize; /* estimated size of data that will be compressed. default = 0xFFFFFFFF.
					   Encoder uses this value to reduce dictionary size */
	int lc;          /* 0 <= lc <= 8, default = 3 */
	int lp;          /* 0 <= lp <= 4, default = 0 */
	int pb;          /* 0 <= pb <= 4, default = 2 */
	int algo;        /* 0 - fast, 1 - normal, default = 1 */
	int fb;          /* 5 <= fb <= 273, default = 32 */
	int btMode;      /* 0 - hashChain Mode, 1 - binTree mode - normal, default = 1 */
	int numHashBytes; /* 2, 3 or 4, default = 4 */
	Poco::UInt32 mc;        /* 1 <= mc <= (1 << 30), default = 32 */
	unsigned writeEndMark;  /* 0 - do not write EOPM, 1 - write EOPM, default = 0 */
	int numThreads;  /* 1 or 2, default = 2 */
} CLzmaEncProps;

void LzmaEncProps_Init(CLzmaEncProps *p);
void LzmaEncProps_Normalize(CLzmaEncProps *p);
Poco::UInt32 LzmaEncProps_GetDictSize(const CLzmaEncProps *props2);



typedef struct
{
	int(*Read)(void *p, void *buf, size_t *size);
	/* if (input(*size) != 0 && output(*size) == 0) means end_of_stream.
	(output(*size) < input(*size)) is allowed */
} ISeqInStream;

typedef struct
{
	size_t(*Write)(void *p, const void *buf, size_t size);
	/* Returns: result - the number of actually written Poco::UInt8s.
	(result < size) means error */
} ISeqOutStream;



/* ---------- CLzmaEncHandle Interface ---------- */

/* LzmaEnc_* functions can return the following exit codes:
Returns:
SZ_OK           - OK
SZ_ERROR_MEM    - Memory allocation error
SZ_ERROR_PARAM  - Incorrect paramater in props
SZ_ERROR_WRITE  - Write callback error.
SZ_ERROR_PROGRESS - some break from progress callback
SZ_ERROR_THREAD - errors in multithreading functions (only for Mt version)
*/

typedef void * CLzmaEncHandle;

CLzmaEncHandle LzmaEnc_Create();
void LzmaEnc_Destroy(CLzmaEncHandle p);
SRes LzmaEnc_SetProps(CLzmaEncHandle p, const CLzmaEncProps *props);
SRes LzmaEnc_WriteProperties(CLzmaEncHandle p, Poco::UInt8 *properties, std::size_t *size);
SRes LzmaEnc_Encode(CLzmaEncHandle p, ISeqOutStream *outStream, ISeqInStream *inStream);
SRes LzmaEnc_MemEncode(CLzmaEncHandle p, Poco::UInt8 *dest, std::size_t *destLen, const Poco::UInt8 *src, std::size_t srcLen, int writeEndMark);

/* ---------- One Call Interface ---------- */

/* LzmaEncode
Return code:
SZ_OK               - OK
SZ_ERROR_MEM        - Memory allocation error
SZ_ERROR_PARAM      - Incorrect paramater
SZ_ERROR_OUTPUT_EOF - output buffer overflow
SZ_ERROR_THREAD     - errors in multithreading functions (only for Mt version)
*/

SRes LzmaEncode(Poco::UInt8 *dest, std::size_t *destLen, const Poco::UInt8 *src, std::size_t srcLen, const CLzmaEncProps *props, Poco::UInt8 *propsEncoded, std::size_t *propsSize, int writeEndMark);


//// Compressor
//
//#define LZMA_PROPS_SIZE 5
//
//typedef struct _CLzmaEncProps
//{
//  Poco::UInt32 dictSize; /* (1 << 12) <= dictSize <= (1 << 27) for 32-bit version
//                      (1 << 12) <= dictSize <= (1 << 30) for 64-bit version
//                       default = (1 << 24) */
//  int lc;          /* 0 <= lc <= 8, default = 3 */
//  int lp;          /* 0 <= lp <= 4, default = 0 */
//  int pb;          /* 0 <= pb <= 4, default = 2 */
//  int fb;          /* 5 <= fb <= 273, default = 32 */
//} CLzmaEncProps;
//
//
//#define SZ_OK 0
//#define SZ_ERROR_DATA 1
//#define SZ_ERROR_MEM 2
//#define SZ_ERROR_CRC 3
//#define SZ_ERROR_UNSUPPORTED 4
//#define SZ_ERROR_PARAM 5
//#define SZ_ERROR_INPUT_EOF 6
//#define SZ_ERROR_OUTPUT_EOF 7
//#define SZ_ERROR_READ 8
//#define SZ_ERROR_WRITE 9
//#define SZ_ERROR_PROGRESS 10
//#define SZ_ERROR_FAIL 11
//#define SZ_ERROR_THREAD 12
//
//#define SZ_ERROR_ARCHIVE 16
//#define SZ_ERROR_NO_ARCHIVE 17
//
#define RINOK(x) { int __result__ = (x); if (__result__ != 0) return __result__; }
//
///* The following interfaces use first parameter as pointer to structure */
//
//#define CHAR_PATH_SEPARATOR '\\'
//#define WCHAR_PATH_SEPARATOR L'\\'
//#define STRING_PATH_SEPARATOR "\\"
//
//
//// Decompressor
//
///* LZMA_REQUIRED_INPUT_MAX = number of required input Poco::UInt8s for worst case.
//   Num bits = log2((2^11 / 31) ^ 22) + 26 < 134 + 26 = 160; */
//
//#define LZMA_REQUIRED_INPUT_MAX 20
//
///* ELzmaFinishMode has meaning only if the decoding reaches output limit !!!
//
//   You must use LZMA_FINISH_END, when you know that current output buffer
//   covers last Poco::UInt8s of block. In other cases you must use LZMA_FINISH_ANY.
//
//   If LZMA decoder sees end marker before reaching output limit, it returns SZ_OK,
//   and output value of destLen will be less than output buffer size limit.
//   You can check status result also.
//
//   You can use multiple checks to test data integrity after full decompression:
//     1) Check Result and "status" variable.
//     2) Check that output(destLen) = uncompressedSize, if you know real uncompressedSize.
//     3) Check that output(srcLen) = compressedSize, if you know real compressedSize.
//        You must use correct finish mode in that case. */
//
//typedef enum
//{
//  LZMA_STATUS_NOT_SPECIFIED,               /* use main error code instead */
//  LZMA_STATUS_FINISHED_WITH_MARK,          /* stream was finished with end mark. */
//  LZMA_STATUS_NOT_FINISHED,                /* stream was not finished */
//  LZMA_STATUS_NEEDS_MORE_INPUT,            /* you must provide more input Poco::UInt8s */
//  LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK  /* there is probability that stream was finished without end mark */
//} ELzmaStatus;
//
//void LzmaEncProps_Init(CLzmaEncProps *p);
//int lzma_encode(Poco::UInt8 *dest, size_t *destLen, const Poco::UInt8 *src, size_t srcLen, const CLzmaEncProps *props, Poco::UInt8 *propsEncoded, size_t *propsSize);
//int lzma_decode(Poco::UInt8* outBuffer, Poco::UInt32* pOutSize, const Poco::UInt8* inBuffer, Poco::UInt32 inSize, ELzmaStatus* status);

SRes lzmaEncode(Poco::UInt8 *dest, std::size_t *destLen, const Poco::UInt8 *src, std::size_t srcLen, const CLzmaEncProps *props, Poco::UInt8 *propsEncoded, std::size_t *propsSize, int writeEndMark);

int lzma_auto_decode(Poco::UInt8* inStream, Poco::UInt32 inSize, Poco::UInt8** outStream, Poco::UInt32* poutSize);

#endif // __SHARED_LZMA_H_
