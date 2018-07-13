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

