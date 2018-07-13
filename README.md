# IASP - Internet of Things Asymmetric Security Protocol

## Introduction

TBD

## Protocol features

TBD

## Demo application description

TBD

## Building instructions

The project is divided into two main parts:
* shared library ```libiasp.so``` which implements core functions of the protocol,
* demo application ```iaspdemo``` which demonstrates usage of the library.

To build the ```iaspdemo``` development binary you can use ```build```
script, which is a simple wrapper for *GNU make*. Type ```./build -c``` to build using a container (see [docker chapter](#docker)).
The ```libiasp.so``` library will be build as a dependecy.

### Makefile description

Makefile targets:
* ```libiasp.so``` - core shared library,
* ```libiasp.a``` - core static library,
* ```iaspdemo``` - demo application,
* ```iaspdemo-static``` - statically linked demo application (useful for development).

Makefile *phony* targets:
* ```all``` - build above mentioned libraries and applications,
* ```clean``` - remove objects,
* ```distclean``` - remove objects and targets (artifacts),
* ```install``` - install demo application and shared library,
* ```install-lib``` - install shared library only,
* ```install-dev``` - install headers and static library,
* ```install-apps``` - install applications (currently only ```iaspdemo```),
* ```install-incs``` - install development headers.

Makefile options:
* ```OPENSSL_PATH``` - use custom OpenSSL build. Useful when you try to detect an API misuse.
* ```LIBIASP_PATH``` - use custom ```libiasp``` build when linking test application.
* ```IASP_DEBUG``` - compile with debugging symbols (```IASP_DEBUG=1```) and no optimization (```-g -O0```). The default value is ```0```.
* ```PREFIX``` - installation prefix (like used in *autotools* projects),
* ```CC```, ```AR``` - can be used to specify ```cc``` and ```ar``` respectively (e.g. for cross-compilation). 


### Docker

The project contains two docker image definiotions:

1. ```Dockerfile```  - release version of a ```iaspdemo``` binary  (**TBD**)
2. ```devel.Dockerfile``` -  development toolchain container which contains build dependencies precompiled development (debug) version of an OpenSSL project. Example usage:
    ```sh
    docker build -t iasp-devel -f devel.Dockerfile .
    docker run --rm \
		--user=$(id -u):$(id -g) \
		--name iasp-devel-builder \
		--mount type=bind,source=$(pwd),target=/target \
		iasp-devel \
		make -r -R -C /target IASP_DEBUG=1 \
        OPENSSL_PATH=/build/openssl \
        LIBIASP_PATH=/target \
        distclean iaspdemo-static
    ```
    The container is used to separate development environment from host
    machine.
    Binding project top directory to a container allows to share sources
    and artifacts between host and container.
