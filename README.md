#### DNS Proxy

[![Build Status](https://travis-ci.org/Ranihilator/dns_proxy.svg?branch=master)](https://travis-ci.org/Ranihilator/dns_proxy)

DNS Proxy with blacklist filter test task

## Build, Test & Run
```shell
   cmake -H. -Bbuild -DCMAKE_BUILD_TYPE=Release
   cmake --build build
   cmake --build build --target helloworld_test
   cmake --build build --target package
   sh -c 'cd build && ctest -V'
   dns_proxy
```

## Debian, Ubuntu install
```shell
    echo "deb http://ppa.launchpad.net/ubuntu-toolchain-r/test/ubuntu trusty main" | sudo tee -a /etc/apt/sources.list
    echo "deb https://dl.bintray.com/ranihilator/projects_for_home_work trusty main" | sudo tee -a /etc/apt/sources.list
    sudo apt-get update && sudo apt-get install dns_proxy
```
