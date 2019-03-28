#ifndef __0CTRL_MSGOBF_H_
#define __0CTRL_MSGOBF_H_

namespace zer0ctrl {

class MsgObf
{
public:
    static std::string deobfuscateData(const std::string& obfData);
    static std::string deobfuscateFromDomain(const std::string& obfData);
    static std::string deobfuscateFromQuery(const std::string& query);
};

}
#endif // __0CTRL_MSGOBF_H_
