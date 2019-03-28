#ifndef __0CTRL_STREAM_H_
#define __0CTRL_STREAM_H_

namespace zer0ctrl {

class Zer0Stream
{
public:
    enum {
        STREAM_SEEK_SET = 0,
        STREAM_SEEK_CUR = 1,
        STREAM_SEEK_END = 2
    };

    Zer0Stream(Poco::UInt32 capacity = 0);
    Zer0Stream(Poco::UInt8* pStream, Poco::UInt32 streamSize);
    ~Zer0Stream();

    Poco::UInt8* begin() { return _buffer.begin(); }
    void read(Poco::UInt8* pData, Poco::UInt32 sz);
    void write(const void* pData, Poco::UInt32 sz);
    void writeDword(Poco::UInt32 val);
    void writeQword(Poco::UInt64 val);
    void writeBinaryString(const char* data, Poco::UInt32 dataSize);
    void writeBinaryString(const std::string& str);
    Poco::UInt32 readDword();
    Poco::UInt64 readQword();
    std::string readBinaryString();

    void clear();
    void seekPos(int offset, int origin);
    void gotoBegin();
    void gotoEnd();

    void writeCrc64();
    bool checkCrc64();

    size_t size() const { return _buffer.size(); }

private:
    void insert(const void* const srcData, const size_t numBytes, size_t insertPosition);

    Poco::Buffer<Poco::UInt8> _buffer;
    int _streamPos;
    bool _exhausted;
};

}

#endif // __0CTRL_STREAM_H_