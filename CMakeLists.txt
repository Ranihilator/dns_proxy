cmake_minimum_required(VERSION 3.2)

if($ENV{TRAVIS_BUILD_NUMBER})
    set(VERSION_BUILD $ENV{TRAVIS_BUILD_NUMBER})
    set(VERSION_BUILD_MAJOR 1)
    set(VERSION_BUILD_MINOR 0)
else()
    set(VERSION_BUILD 1)
    set(VERSION_BUILD_MAJOR 1)
    set(VERSION_BUILD_MINOR 0)
endif()

project(dns_proxy VERSION ${VERSION_BUILD_MAJOR}.${VERSION_BUILD_MINOR}.${VERSION_BUILD})

find_package (Threads)
#configure_file(version.h.in ${HEADER_PATH}/version.h)

set(INI_PATH "${PROJECT_SOURCE_DIR}/ini/src")

set(HEADER_FILES defines.h proxy/proxy.h proxy/dns/dns.h proxy/dns/type.h ${INI_PATH}/ini.h)
set(SOURCE_FILES signal_handler.c proxy/proxy.c proxy/dns/dns.c ${INI_PATH}/ini.c)

add_executable(dns_proxy ${PROJECT_SOURCE_DIR}/main.c ${HEADER_FILES} ${SOURCE_FILES})

set_target_properties(dns_proxy PROPERTIES
  C_STANDARD 11
  C_STANDARD_REQUIRED ON
  COMPILE_OPTIONS -Wpedantic -Wall -Wextra
)

target_link_libraries (dns_proxy ${CMAKE_THREAD_LIBS_INIT})


install(TARGETS dns_proxy RUNTIME DESTINATION bin COMPONENT dns_proxy)

set(CPACK_GENERATOR DEB)

set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")

set(CPACK_PACKAGE_CONTACT ranihilaltor@gmail.com)

include (CPack)
