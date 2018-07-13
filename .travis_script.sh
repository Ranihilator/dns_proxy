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


fi
