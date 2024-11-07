# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2020 Metrological
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 2.8)
project(DRMPlayready)

if (DEFINED MAKE_VERBOSE)
    set(CMAKE_VERBOSE_MAKEFILE TRUE)
endif()

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(DRM_PLUGIN_NAME "PlayReady4")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

if(NOT CMAKE_CROSSCOMPILING)
   set(STAGING_DIR "${CMAKE_INSTALL_PREFIX}")
else()
   set(STAGING_DIR "${CMAKE_FIND_ROOT_PATH}")
endif()

file(GLOB DRM_PLUGIN_INCLUDES *.h)

set(DRM_PLUGIN_LIBS 
    ${PLAYREADY4_LIBRARIES})

set(DRM_PLUGIN_SOURCES 
    MediaSession.cpp 
    MediaSystem.cpp
    MediaSessionExt.cpp)

# add the library
add_library(${DRM_PLUGIN_NAME} SHARED ${DRM_PLUGIN_SOURCES})
target_compile_definitions(${DRM_PLUGIN_NAME} PRIVATE ${PLAYREADY4_FLAGS})
target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${PLAYREADY4_INCLUDE_DIRS})
target_include_directories(${DRM_PLUGIN_NAME} PRIVATE source/curl_prebuilt/include/curl source/inc source/modules/contentspecific/h264/real source/oem/ansi/inc source/oem/common/broker/pkImpl source/oem/common/crypto/aes source/oem/common/inc source/oem/common/trustedexec source/results source/securecore/trustedexec/base source/tools/devicedevcert/bcertdump source/tools/pseudotee/dll source/tools/shared/common source/tools/shared/netio source/tools/shared/oem source/tools/shared/remoteprovisioningmock source/trustedexec/base source/trustedexec/debug source/trustedexec/decrypt source/trustedexec/inc source/trustedexec/licprep source/trustedexec/rprov source/trustedexec/teeproxystub/common source/trustedexec/teeproxystub/proxy/common source/trustedexec/teeproxystub/stub/common)
add_compile_definitions(DRM_BUILD_PROFILE=900)
target_link_libraries(${DRM_PLUGIN_NAME} PRIVATE libplayreadypk.so)
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES PREFIX "")

find_package(OpenSSL REQUIRED)
target_link_libraries(${DRM_PLUGIN_NAME} OpenSSL::SSL)

# Enable SVP.
#if("${RDK_SVP}" STREQUAL "ENABLED")
    message(STATUS "Using RDK_SVP")
    add_definitions (-DUSE_SVP)
    target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CMAKE_SYSROOT}/usr/include/gstreamer-1.0)
    target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CMAKE_SYSROOT}/usr/include/glib-2.0)
    target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CMAKE_SYSROOT}/usr/lib/glib-2.0/include)
    target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CMAKE_SYSROOT}/usr/include/realtek/genericLinux/include)
    target_link_libraries(${DRM_PLUGIN_NAME} gstsvpext)
#endif()

add_definitions(-DNO_PERSISTENT_LICENSE_CHECK=1)

install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/WPEFramework/OCDM)
