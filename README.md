# Shadowsocks boost::asio port

## Introduction

This is a simple port of shadowsocks.

*I'm a little busy these days... Will be back at Sept.*

## Build from source

- [windows](#windows)

- [debian](#debian)

- [macos](#macos)

### Windows

##### Prepare

* Install [vcpkg](https://github.com/Microsoft/vcpkg) and [cmake](https://cmake.org).

* Set environment variables ```VCPKG_DEFAULT_TRIPLET=x64-windows-static```, ```VCPKG_ROOT={Path to your vcpkg repo}```

* Install dependencies:

```
.\vcpkg.exe install openssl libsodium gflags glog boost-system boost-asio boost-program-options boost-process boost-format
```

##### Clone repo and build

```
git clone https://github.com/lcdtyph/shadowsocks-asio
cd shadowsocks-asio
.\build-win.ps1
```

##### Install

Following command will install binaries and dlls into %HOMEPATH%\Documents\bin

```
cmake --build . --target INSTALL --config Release
```

### Debian

##### Prepare

* Install the latest [cmake](https://cmake.org)

* Build the latest [boost](https://boost.org) from source

```bash
# change into boost source directory
./bootstrap.sh --with-libraries=system,program_options,filesystem
./b2 cxxflags=-fPIC threading=multi -j2
./b2 install
```

* Build libsodium from source

```bash
apt install -y autoconf libtool
# change into libsodium source directory
./autogen.sh
./configure --with-pic=yes
make -j2 install
ldconfig
```

* Install rest dependencies

```bash
apt install build-essential git-core libgoogle-glog-dev libssl1.0-dev
```

##### Clone repo and build

```bash
git clone https://github.com/lcdtyph/shadowsocks-asio
cd shadowsocks-asio
cmake . && make -j2
```

##### Install

```bash
make install
ldconfig
```

### macOS

##### Prepare

```bash
brew install cmake libsodium openssl boost glog gflags
```

##### Clone repo and build

```bash
git clone https://github.com/lcdtyph/shadowsocks-asio
cd shadowsocks-asio
cmake . && make -j2
```

##### Install

```bash
make install
```

## TODO

- ~~ss-server~~ (done)
- ~~stream ciphers~~ (done)
- friendly help message
- ~~cross-platform support~~ (done)
- udp relay (current only available for ss-server)
- ~~obfs plugin~~ (done)
- ~~http obfs, uri support~~ (done)
- ~~session management~~ (done)
- replace boost::program_options with gflags
- more obfuscator
- ~~tunnel~~ (done)
- obfs failover

## License

>lcdtyph <lcdtyph@gmail.com>
Copyright (C) 2018  lcdtyph
>
>This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
>
>This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
>
>You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
