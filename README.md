> `socks5d` is a SOCKSv5 Proxy service capable of attending multiple connections with non-blocking operations. This service comes included with a SCTP service which is capable of configuring and monitoring the SOCKSv5 server.

## Table of Contents

[**Installation**](#installation)

* [**Compile**](#compile)

* [**Artifacts Location**](#artifacts-location)

[**Usage**](#usage)

* [**Socks5d**](#socks5d)

* [**Client**](#client)

[**Documentation**](#documentation)


[**Contributors**](#contributors)

[**Code Credits**](#code-credits)

## Installation
### Compile 
This project uses CMAKE for the generation of the compilation code. In order to compile the code you need to run the following commands in the project's root folder:
```bash
mkdir build
cd build
cmake ../
make
```
Where is the desired build directory. This will generate all the binary files required for running the application in the ```/build/bin``` directory.

### Artifacts Location
Once compiled using the previous steps the following artefacts will be generated in the ``/build/bin`` directory:
* ```socks5d```Binary file for the SOCKSv5 Server.
* ```client``` Binary file for test client which communicates with the configuration and monitor service of the SOCKSv5 server.

## Usage
### Socks5d
In order to run the SOCKSv5 Service you can execute it using the following command:
```bash
./socks5d <arguments>
```
Where the accepted arguments are the following:

```
--doh-ip addr
     Establishes the DoH server IP address. Default: "127.0.0.1".

--doh-port port
     Establishes the DoH server port. Default: 8053.

--doh-host hostname
     Establishes the DoH host header. Default: "localhost".

--doh-path path
     Establishes the DoH request path. Default: "/getnsrecord".

--doh-query query
     Establishes the DoH query in case of using GET method (DoH uses POST method, therefore this is unused). Default: "?dns=".
     
-h     
     Prints help

-l dirección-http
     Establece la dirección donde servirá el proxy SOCKS.  Por defecto escucha en todas las interfaces.

-N     
     Disables passwords disectors.

-L addr
     Establishes the IP address where configuration and monitor service accepts connections. Default: loopback

-p port
     TCP Port where SOCKSv5 service listens for connections. Default: 1080.

-P port
     SCTP Port where the configuration and monitor service accepts connections. Default: 8080.

-u user:pass
     Establishes username and password for the SOCKSv5 service. May establish upto 10 users.

-U user:pass
     Establishes administrator user for the configuration and monitor service. May establish only 1 administrator.

-v      
     Prints information about the current version.
```
For more information, please refer to the Man Page in the documentation section

### Client
In order to run the Configuration and Monitor service test client you need to execute the following command:
```bash
./client <port_number> <hostname> <username> <password> <option> [parameters]
```
Where each argument refers to:

```text
<port_number> - Configuration and Monitor port
<hostname>    - Configuration and Monitor hostname
<username>    - Configuration and Monitor administrator username
<password>    - Configuration and Monitor administrator password
<option>      - Configuration and Monitor administrator method option
[parameters]  - Configuration and Monitor administrator method parameters
```

The accepted option methods are the following:
```text
1 Get the number of historical connections
2 Get the number of concurrent connections
3 Get the number of bytes transferred 
4 Set a new buffer size. Accepts only 1 parameter (buffer size)
```
For more information, please refer to the RFC in the documentation section

## Documentation
Documentation of the services provided can be found in the doc directory where the following documentations can be found:

```socks5d.8 ``` Man page of the SOCKSv5 service

```RFC.pdf``` RFC of the configuration and monitor protocol

```Informe TPE pc-2020b-6.pdf``` Academic report

### Contributors
* Méndez, Ignacio Alberto   -   59058
* Griggio, Juan Gabriel     -   59092
* Villanueva, Ignacio       -   59000
* Zuberbuhler, Ximena       -   57287

### Code Credits
- Base64: https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/
- Buffer Library: Library provided by lecturer
- Args Library: Library provided by lecturer
- Netutils Library: Library provided by lecturer
- Selector Library: Library provided by lecturer
- STM Library: Library provided by lecturer

