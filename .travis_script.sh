#!/bin/bash

ACTION="${1}"

if [[ ${ACTION} == 'build' ]]; then

    echo "Building..."

    doxygen -u
    doxygen
    
    mkdir -p dist doc build
    cmake -H. -Bbuild -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    cmake --build build --target
    cmake --build build --target package

    mv build/*.deb dist/

elif [[ ${ACTION} == 'deploy' ]]; then

    echo "Deploying..."

    curl -T dist/dns_proxy-1.0.$TRAVIS_BUILD_NUMBER-amd64.deb -u $BINTRAY_USER:$BINTRAY_API_KEY "https://api.bintray.com/content/$BINTRAY_USER/projects_for_home_work/dns_proxy/1.0/pool/d/dns_proxy-1.0.$TRAVIS_BUILD_NUMBER-Linux.deb;deb_distribution=trusty;deb_component=main;deb_architecture=amd64;publish=1"

fi
