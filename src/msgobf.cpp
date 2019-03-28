#include "common.h"
#include "msgobf.h"

namespace zer0ctrl {

std::string MsgObf::deobfuscateData(const std::string& obfData)
{
    std::string data;
    int i, lowPart, highPart;
    static const char symTable[36] = { '0', '1', '2', '3', '4', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '5', '6', '7', '8', '9' };

    for (i = 0; i < obfData.size(); ++i) {
        char ch;
        int rndOffset = obfData[i++] - 'a';
        if (rndOffset < 0 || rndOffset > 20) {
            throw Poco::DataFormatException("deobfuscateData() (1):" + obfData);
        }
        ch = obfData[i++];
        for (lowPart = 0; lowPart < sizeof(symTable); ++lowPart) {
            if (ch == symTable[lowPart]) {
                break;
            }
        }
        lowPart -= rndOffset;
        if (lowPart >= sizeof(symTable) || lowPart < 0) {
            throw Poco::DataFormatException("deobfuscateData() (2):" + obfData);
        }
        ch = obfData[i];
        for (highPart = 0; highPart < sizeof(symTable); ++highPart) {
            if (ch == symTable[highPart]) {
                break;
            }
        }
        highPart -= rndOffset;
        if (highPart >= sizeof(symTable) || highPart < 0) {
            throw Poco::DataFormatException("deobfuscateData() (3):" + obfData);
        }
        data += (char)((highPart << 4) + lowPart);
    }

    return data;
}

std::string MsgObf::deobfuscateFromDomain(const std::string& obfData)
{
    std::string data;
    std::string ret;
    std::string::const_iterator itr, end;

    for (end = obfData.end(); --end >= obfData.begin();) {
        if (*end == '.') {
            data = obfData.substr(0, end - obfData.begin());
            break;
        }
    }

    for (itr = data.begin(); itr != data.end(); ++itr) {
        if (*itr != '.') {
            ret += *itr;
        }
    }

    return MsgObf::deobfuscateData(ret);
}

std::string MsgObf::deobfuscateFromQuery(const std::string& query)
{
    std::string data, obfData = query;
    std::string::const_iterator itr;

    for (itr = obfData.begin(); itr != obfData.end(); ++itr) {
        if (*itr == '/' || *itr == '&' || *itr == '=' || *itr == '.' || *itr == '?') {
            continue;
        }
        data += *itr;
    }

    obfData = data;
    data.clear();

    itr = obfData.begin();
    int dummyNum = (int)(*(itr++) - 'a');
    if (dummyNum < 3 || dummyNum > 7) {
        throw Poco::DataFormatException("Incorrect dummyNum value in obfuscated query: " + Poco::NumberFormatter::format(dummyNum));
    }

    for (; itr < obfData.end();) {
        data += *(itr++);

        if (itr >= obfData.end()) {
            throw Poco::DataFormatException("Incorrect data in obfuscated query:" + obfData);
        }

        for (int k = 0; itr < obfData.end() && k < dummyNum; ++k, ++itr);
    }

    return data;
}

}
