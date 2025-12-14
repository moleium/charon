# charon

A network protocol analysis and interception framework for Gaijin Entertainment's proprietary "Char" server infrastructure, used by games built on the Dagor Engine.

UDP is yet to be implemented.

## Prerequisites

*   A C++ compiler supporting the C++23 standard (Clang, MSVC, or GCC).
*   CMake (version 3.30 or newer).
*   All submodules are included in the repository.

## Building

```sh
git clone --recursive https://github.com/moleium/charon
cd charon

mkdir build && cd build
cmake ..

cmake --build . --config Release
```

## Usage

This utility requires manual configuration before it can work.

You need to use a network analysis tool (like Wireshark) to find the domain name of the game server your client is connecting to (e.g., mgate-sv-nl-01.[redacted].com).
Then modify your system `hosts` file and add an entry to redirect this domain to your local machine.

```
127.0.0.1 mgate-sv-nl-01.[redacted].com
```

Additionally, the IP address of the server is hardcoded in the [patcher](src/utils/patcher.hpp). You need to find the real IP address of the game server from Step 1.

**Note**: The pattern used to find the patching location in the [patcher](src/utils/patcher.hpp) is hardcoded for a specific version of [redacted].

## Disclaimer

This project is intended strictly for educational and research purposes.
