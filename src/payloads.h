#ifndef __0CTRL_PAYLOADS_H_
#define __0CTRL_PAYLOADS_H_

namespace zer0ctrl {

class PayloadsManager
{
public:
	typedef std::pair<Poco::UInt64, ZBuffer*> ZPayload;
	typedef std::map<Poco::UInt32, ZPayload> ZPayloadMap;

	PayloadsManager();
	~PayloadsManager();

	ZPayload* getPayload(const Poco::UInt32 hash);

	static PayloadsManager* getInstance();

	void init();

private:
	void addPayload(const std::string& name, const Poco::File& f);
	

	void onItemAdded(const Poco::DirectoryWatcher::DirectoryEvent& ev);
	void onItemRemoved(const Poco::DirectoryWatcher::DirectoryEvent& ev);
	void onItemModified(const Poco::DirectoryWatcher::DirectoryEvent& ev);

	ZPayloadMap _payloadMap;
	Poco::DirectoryWatcher _watcher;
	Poco::FastMutex _mutex;
};

}

#endif // __0CTRL_PAYLOADS_H_
