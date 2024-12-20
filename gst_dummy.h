#pragma once

#include "MediaSession.h"
#include <cdmi.h>
#include <string>

namespace CDMi {


    class Config : public WPEFramework::Core::JSON::Container {
        private:
	        Config& operator= (const Config&);
		    public:
		            Config () 
	                    : ReadDir()
		            , StoreLocation() 
			    , MeteringCertificate() {
		            Add("read-dir", &ReadDir);
		            Add("store-location", &StoreLocation);
		            Add("home-path", &HomePath);
			    Add(_T("metering"), &MeteringCertificate); //for brcm
                            }

			    Config (const Config& copy) 
  			    : ReadDir(copy.ReadDir)
			    , StoreLocation(copy.StoreLocation)
                            , HomePath(copy.HomePath) {
			    Add("read-dir", &ReadDir);
			    Add("store-location", &StoreLocation);
			    Add("home-path", &HomePath);
			    Add(_T("metering"), &MeteringCertificate); //for brcm
                            }
																							        virtual ~Config() {
       }
    public:
            WPEFramework::Core::JSON::String ReadDir;
            WPEFramework::Core::JSON::String StoreLocation;
            WPEFramework::Core::JSON::String HomePath;
            WPEFramework::Core::JSON::String MeteringCertificate;
            CDMi_RESULT SetSecureStopPublisherCert( const DRM_BYTE*, DRM_DWORD  ); // needs to be handled
       };

struct ConfigPaths {
        std::string persistentPath;
        std::string readDir;
        std::string storeLocation;
	std::string statePath;
	std::string storePath;
	};

//*******************getDrmOemContext--> function to get oem context for brcm****************************************************//
DRM_RESULT getDrmOemContext(DRM_VOID** m_drmOemContext) {
        DRM_RESULT dr = DRM_SUCCESS;
	m_drmOemContext = nullptr;
	        return dr;
		}


 //*******************getSoCDrmPath---> function to get SoC specific DRM path*********************************//
ConfigPaths getSoCDrmPath(const WPEFramework::PluginHost::IShell* shell, const std::string& configline) {
    ConfigPaths paths;
    Config config;
    config.FromString(configline);
    paths.persistentPath = "";
    paths.storePath = "";
    paths.readDir = config.ReadDir.Value();
 // paths.storeLocation = config.StoreLocation.Value(); //this line was commented in realtek
    paths.storeLocation = "/opt/drm/sample.hds";
    paths.statePath = config.HomePath.Value().c_str();
    return paths;
    }
}
