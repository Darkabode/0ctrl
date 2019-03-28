#include "common.h"

#ifdef _WIN32
#include <intrin.h>
#endif // _WIN32

namespace zer0ctrl {

Globals::Globals()   
{
}

Globals::~Globals()
{
    delete _pQueryPool;
    delete _pMysqlPool;
    Poco::Data::MySQL::Connector::unregisterConnector();
}

void Globals::init(Poco::Util::LayeredConfiguration& config)
{
    _poolMinSize = config.getInt("mempool.min_size", 100);
    _poolMaxSize = config.getInt("mempool.max_size", 300);
	_nodesPath = config.getString("path.nodes", "data");
    _modulesPath = config.getString("path.modules", "/usr/local/etc/zer0/modules");
	_payloadsPath = config.getString("path.payloads", "/usr/local/etc/zer0/payloads");
    
    _pQueryPool = new Poco::MemoryPool(1024, _poolMinSize, _poolMaxSize);
    _pMysqlPool = new Poco::Data::SessionPool(Poco::Data::MySQL::Connector::KEY, config.getString("db.conn"), 1, 128);

    Poco::Data::MySQL::Connector::registerConnector();

    Poco::Data::Session session = _pMysqlPool->get();
    Poco::Data::Statement insert(session);
    std::vector<std::string> ztables;
    std::vector<Poco::UInt32> buildIds;
    insert << "SELECT build_id,ztable FROM builds WHERE status='Active'",
        Poco::Data::Keywords::into(buildIds),
        Poco::Data::Keywords::into(ztables);
    insert.execute();

    for (int i = 0; i < buildIds.size(); ++i) {
        std::string& ztable = ztables.at(i);
        _ztableMap.insert(std::make_pair(buildIds.at(i), new ZBuffer((const Poco::UInt8*)&ztable[0], ztable.length())));
    }
}

Globals* Globals::getInstance()
{
    static Poco::SingletonHolder<Globals> singleton;
    return singleton.get();
}

bool Globals::hasZtableWithId(Poco::UInt32 buildId)
{
    return (_ztableMap.find(buildId) != _ztableMap.end());
}

ZBuffer* Globals::getZtableForId(Poco::UInt32 buildId)
{
    bool isEnd;
    ZBuffer* pZtable = 0;
    _ztablesMutex.lock();
    std::map<Poco::UInt32, ZBuffer* >::iterator itr = _ztableMap.find(buildId);
    isEnd = (itr == _ztableMap.end());
    if (!isEnd) {
        pZtable = itr->second;
        _ztablesMutex.unlock();
    }
    else {
        _ztablesMutex.unlock();

        Poco::Data::Session session = _pMysqlPool->get();
        Poco::Data::Statement insert(session);
        std::vector<std::string> ztables;
        insert << "SELECT ztable FROM builds WHERE status='Active' AND build_id=?",
            Poco::Data::Keywords::into(ztables),
            Poco::Data::Keywords::use(buildId);
        insert.execute();

        if (ztables.size() > 0) {
            std::string& ztable = ztables.at(0);
            _ztablesMutex.lock();
            _ztableMap.insert(std::make_pair(buildId, new ZBuffer((const Poco::UInt8*)&ztable[0], ztable.length())));
            itr = _ztableMap.find(buildId);
            isEnd = (itr == _ztableMap.end());
            if (!isEnd) {
                pZtable = itr->second;
            }
            _ztablesMutex.unlock();
        }
    }

    return pZtable;
}

void Globals::readFile(const std::string& filePath, std::string& data)
{
    Poco::File file(filePath);
    if (!file.exists()) {
        throw Poco::FileNotFoundException(filePath);
    }
    Poco::FileInputStream iStream(filePath, std::ios::in | std::ios::binary);
    if (!iStream.good()) {
        throw Poco::FileException("Can't read " + filePath);
    }

    if (file.getSize() > 0) {
        data.resize((std::size_t)file.getSize());
        iStream.read(&data[0], (std::streamsize)file.getSize());
        iStream.close();
    }
}

void Globals::saveFile(const std::string& filePath, std::string& data)
{
    Poco::FileOutputStream oStream(filePath, std::ios::out | std::ios::binary);
    if (!oStream.good()) {
        throw Poco::FileException("Can't write " + filePath);
    }

    if (data.length() > 0) {
        oStream.write(&data[0], data.length());
        oStream.close();
    }
}

Poco::UInt32 Globals::ror(Poco::UInt32 value, int places)
{
    return (value >> places) | (value << (32 - places));
}

Poco::UInt32 Globals::getHash(const char* pszString)
{
    char ch;
    Poco::UInt32 dwData = 0;
    while (*pszString != '\0') {
        ch = *(pszString++) | 0x20;
        dwData = ror(dwData, 11);
        dwData += (Poco::UInt32)ch;
    }
    return dwData;
}

void Globals::arc4(Poco::UInt8* buffer, Poco::UInt32 length, const Poco::UInt8* key, Poco::UInt32 keylen)
{
    int a, b;
    Poco::UInt32 i, j = 0, k = 0;
    Poco::UInt8 m[256];

    for (i = 0; i < 256; ++i) {
        m[i] = (Poco::UInt8)i;
    }

    for (i = 0; i < 256; ++i, ++k) {
        if (k >= keylen) {
            k = 0;
        }

        a = m[i];
        j = (j + a + key[k]) & 0xFF;
        m[i] = m[j];
        m[j] = (Poco::UInt8)a;
    }

    j = k = 0;

    for (i = 0; i < length; ++i) {
        j = (j + 1) & 0xFF;
        a = m[j];
        k = (k + a) & 0xFF;
        b = m[k];

        m[j] = (Poco::UInt8)b;
        m[k] = (Poco::UInt8)a;

        buffer[i] = (Poco::UInt8)(buffer[i] ^ m[(Poco::UInt8)(a + b)]);
    }
}


#define POLY 0xc96c5795d7870f42ULL

Poco::UInt64 crc64_little_table[8][256] = { 0 };

int _tableInited = 0;

Poco::UInt64 Globals::crc64(Poco::UInt64 crc, void* buf, size_t len)
{
    unsigned char* next = (unsigned char*)buf;

    if (!_tableInited) {
        _tableInited = 1;
        unsigned n, k;
        Poco::UInt64 crc;

        /* generate CRC-64's for all single byte sequences */
        for (n = 0; n < 256; ++n) {
            crc = n;
            for (k = 0; k < 8; ++k) {
                crc = crc & 1 ? POLY ^ (crc >> 1) : crc >> 1;
            }
            crc64_little_table[0][n] = crc;
        }

        /* generate CRC-64's for those followed by 1 to 7 zeros */
        for (n = 0; n < 256; ++n) {
            crc = crc64_little_table[0][n];
            for (k = 1; k < 8; ++k) {
                crc = crc64_little_table[0][crc & 0xff] ^ (crc >> 8);
                crc64_little_table[k][n] = crc;
            }
        }
    }
    crc = ~crc;
    while (len && ((size_t)next & 7) != 0) {
        crc = crc64_little_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        --len;
    }
    while (len >= 8) {
        crc ^= *(Poco::UInt64 *)next;
        crc = crc64_little_table[7][crc & 0xff] ^
            crc64_little_table[6][(crc >> 8) & 0xff] ^
            crc64_little_table[5][(crc >> 16) & 0xff] ^
            crc64_little_table[4][(crc >> 24) & 0xff] ^
            crc64_little_table[3][(crc >> 32) & 0xff] ^
            crc64_little_table[2][(crc >> 40) & 0xff] ^
            crc64_little_table[1][(crc >> 48) & 0xff] ^
            crc64_little_table[0][crc >> 56];
        next += 8;
        len -= 8;
    }
    while (len) {
        crc = crc64_little_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        --len;
    }
    return ~crc;
}

}
