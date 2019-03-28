#include "common.h"
#include "stream.h"

namespace zer0ctrl {

Zer0Stream::Zer0Stream(Poco::UInt32 capacity) :
_buffer(capacity),
_streamPos(0),
_exhausted(false)
{
}

Zer0Stream::Zer0Stream(Poco::UInt8* pStream, Poco::UInt32 streamSize) :
_buffer(pStream, streamSize),
_streamPos(0),
_exhausted(false)
{

}

Zer0Stream::~Zer0Stream()
{

}

void Zer0Stream::read(Poco::UInt8* pData, Poco::UInt32 sz)
{
    if ((_streamPos + sz) <= _buffer.size()) {
        memcpy(pData, _buffer.begin() + _streamPos, sz);
        _streamPos += sz;
    }
    else {
        throw Poco::DataException("No data in stream");
    }
}

void Zer0Stream::write(const void* pData, Poco::UInt32 sz)
{
    if ((_streamPos + sz) <= _buffer.size()) {
        memcpy(_buffer.begin() + _streamPos, pData, sz);
    }
    else {
        insert(pData, sz, _streamPos);
    }
    _streamPos += sz;
}

void Zer0Stream::insert(const void* const srcData, const size_t numBytes, size_t insertPosition)
{
    if (numBytes > 0) {
        insertPosition = std::min(_buffer.size(), insertPosition);
        const size_t trailingDataSize = _buffer.size() - insertPosition;
        _buffer.resize(_buffer.size() + numBytes);
        
        if (trailingDataSize > 0) {
            memmove(_buffer.begin() + insertPosition + numBytes, _buffer.begin() + insertPosition, trailingDataSize);
        }
        memcpy(_buffer.begin() + insertPosition, srcData, numBytes);
    }
}

void Zer0Stream::writeDword(Poco::UInt32 val)
{
    write((Poco::UInt8*)&val, sizeof(Poco::UInt32));
}

void Zer0Stream::writeQword(Poco::UInt64 val)
{
    write((Poco::UInt8*)&val, sizeof(Poco::UInt64));
}

void Zer0Stream::writeBinaryString(const char* data, Poco::UInt32 dataSize)
{
    write((Poco::UInt8*)&dataSize, sizeof(Poco::UInt32));
    if (dataSize > 0 && data != 0) {
        write((Poco::UInt8*)data, dataSize);
    }
}

void Zer0Stream::writeBinaryString(const std::string& str)
{
    writeBinaryString(str.c_str(), str.length());
}

Poco::UInt32 Zer0Stream::readDword()
{
    Poco::UInt32 val = 0;
    read((Poco::UInt8*)&val, sizeof(Poco::UInt32));

    return val;
}

Poco::UInt64 Zer0Stream::readQword()
{
    Poco::UInt64 val = 0;
    read((Poco::UInt8*)&val, sizeof(Poco::UInt64));

    return val;
}

std::string Zer0Stream::readBinaryString()
{
    std::string str;
    Poco::UInt32 strSize = 0;
    read((Poco::UInt8*)&strSize, sizeof(Poco::UInt32));

    if (strSize > 0) {
        str.resize(strSize);
        read((Poco::UInt8*)&str[0], strSize);
    }

    return str;
}

void Zer0Stream::clear()
{
    _buffer.setCapacity(0, false);
    _exhausted = false;
    _streamPos = 0;
}

void Zer0Stream::seekPos(int offset, int origin)
{
    switch (origin) {
        case STREAM_SEEK_CUR: {
            _streamPos += offset;
            _streamPos = std::max(0, _streamPos);
            _streamPos = std::min(_streamPos, (int)_buffer.size());
            break;
        }
        case STREAM_SEEK_SET: {
            _streamPos = std::max(0, offset);
            break;
        }
        case STREAM_SEEK_END: {
            _streamPos = _buffer.size() + offset;
            _streamPos = std::min(_streamPos, (int)_buffer.size());
            break;
        }
    }
}

void Zer0Stream::gotoBegin()
{
    _streamPos = 0;
}

void Zer0Stream::gotoEnd()
{
    _streamPos = _buffer.size();
}

void Zer0Stream::writeCrc64()
{
    size_t sz = _buffer.size();
    Poco::UInt64 crc = Globals::crc64(0, _buffer.begin(), sz);
    gotoEnd();
    writeQword(crc);
}

bool Zer0Stream::checkCrc64()
{
    Poco::UInt64 crc;
    Poco::UInt64 realCrc = Globals::crc64(0, _buffer.begin(), _buffer.size() - sizeof(Poco::UInt64));
    int prePos = _streamPos;
    
    seekPos(-8, STREAM_SEEK_END);
    crc = readQword();
    seekPos(prePos, STREAM_SEEK_SET);
    return (crc == realCrc);
}

}
