#include "common.h"
#include "payloads.h"

namespace zer0ctrl {

PayloadsManager::PayloadsManager() :
_watcher((const std::string&)Globals::getInstance()->_payloadsPath, Poco::DirectoryWatcher::DW_ITEM_ADDED | Poco::DirectoryWatcher::DW_ITEM_REMOVED | Poco::DirectoryWatcher::DW_ITEM_MODIFIED, 10)
{
	
}

PayloadsManager::~PayloadsManager()
{
	for (ZPayloadMap::iterator itr = _payloadMap.begin(); itr != _payloadMap.end(); ++itr) {
		delete itr->second.second;
	}
}

PayloadsManager* PayloadsManager::getInstance()
{
	static Poco::SingletonHolder<PayloadsManager> _singleton;
	return _singleton.get();
}

void PayloadsManager::init()
{
	// Load payloads
	Poco::DirectoryIterator itr((const std::string&)"./payloads");
	Poco::DirectoryIterator endItr;

	for (; itr != endItr; ++itr) {
		addPayload(itr.name(), *itr);
	}

	_watcher.itemAdded += Poco::delegate(this, &PayloadsManager::onItemAdded);
	_watcher.itemRemoved += Poco::delegate(this, &PayloadsManager::onItemRemoved);
	_watcher.itemModified += Poco::delegate(this, &PayloadsManager::onItemModified);
}

void PayloadsManager::addPayload(const std::string& name, const Poco::File& f)
{
	std::string fileData;
	Globals::readFile(f.path(), fileData);
	_payloadMap.insert(std::make_pair(Globals::getHash(&name[0]), std::make_pair(Globals::crc64(0, &fileData[0], fileData.length()), new ZBuffer((const Poco::UInt8*)&fileData[0], fileData.length()))));
}

void PayloadsManager::onItemAdded(const Poco::DirectoryWatcher::DirectoryEvent& ev)
{
	try {
		Poco::ScopedLock<Poco::FastMutex> lock(_mutex);
		Poco::Path p(ev.item.path());
		addPayload(p.getFileName(), ev.item.path());
	}
	catch (Poco::Exception& exc) {
		Poco::Util::Application::instance().logger().error(exc.displayText());
	}
}

void PayloadsManager::onItemRemoved(const Poco::DirectoryWatcher::DirectoryEvent& ev)
{
	try {
		Poco::ScopedLock<Poco::FastMutex> lock(_mutex);
		Poco::Path p(ev.item.path());
		Poco::UInt32 hash = Globals::getHash(&p.getFileName()[0]);

		ZPayloadMap::iterator itr = _payloadMap.find(hash);
		if (itr != _payloadMap.end()) {
			delete itr->second.second;
			_payloadMap.erase(itr);
		}
	}
	catch (Poco::Exception& exc) {
		Poco::Util::Application::instance().logger().error(exc.displayText());
	}
}

void PayloadsManager::onItemModified(const Poco::DirectoryWatcher::DirectoryEvent& ev)
{
	try {
		Poco::ScopedLock<Poco::FastMutex> lock(_mutex);
		Poco::Path p(ev.item.path());
		Poco::UInt32 hash = Globals::getHash(&p.getFileName()[0]);

		ZPayloadMap::iterator itr = _payloadMap.find(hash);
		if (itr != _payloadMap.end()) {
			std::string fileData;
			Globals::readFile(ev.item.path(), fileData);
			Poco::UInt64 crc64 = Globals::crc64(0, &fileData[0], fileData.length());
			if (itr->second.first != crc64) {
				itr->second.first = crc64;
				delete itr->second.second;
				itr->second.second = new ZBuffer((const Poco::UInt8*)&fileData[0], fileData.length());
			}
		}
	}
	catch (Poco::Exception& exc) {
		Poco::Util::Application::instance().logger().error(exc.displayText());
	}
}

PayloadsManager::ZPayload* PayloadsManager::getPayload(const Poco::UInt32 hash)
{
	Poco::ScopedLock<Poco::FastMutex> lock(_mutex);

	std::map<Poco::UInt32, ZPayload>::iterator itr = _payloadMap.find(hash);
	if (itr != _payloadMap.end()) {
		return &(itr->second);
	}
	return 0;
}

}