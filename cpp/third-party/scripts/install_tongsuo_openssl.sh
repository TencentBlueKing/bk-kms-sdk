#!/usr/bin/env bash
set -eo pipefail
source $( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )/base.sh

# install Tongsuo openssl
# version 8.3.2
# source https://github.com/Tongsuo-Project/Tongsuo/archive/refs/tags/8.3.2.tar.gz
name="tongsuo_openssl"
version="8.3.2"

# handle the args from caller
dir="$1"
if [[ -z "$dir" ]]; then
    dir="/tmp/bk-gse-thirdparty/$name"
fi
fd="$2"
if [[ -z "$fd" ]]; then
    fd="1"
fi
head_width="$3"
if [[ -z "$head_width" ]]; then
    head_width=1
fi
progress() {
    printf "$COLOR_SUCC %-${head_width}s $COLOR_OFF$@\n" "[$name]" >&$fd
}
fail() {
    printf "$COLOR_FAIL %-${head_width}s $COLOR_OFF$@\n" "[$name]" >&$fd
}

# ensure dir
mkdir -p $dir
cd $dir

progress "checking $name"
need_install=0
hash openssl &> /dev/null || need_install=1
if [[ "$need_install" == "1" ]]; then
    progress "installing $name"

    # download source
    progress "downloading"
    wget --no-check-certificate https://github.com/Tongsuo-Project/Tongsuo/archive/refs/tags/8.3.2.tar.gz
    tar zxvf 8.3.2.tar.gz
    cd Tongsuo-8.3.2/

    # compile
    progress "compiling & installing"
    ./config shared --prefix=/usr/local --openssldir=/usr/local/include/openssl
    make depend
    make -j4

    # installing
    progress "installing"
    make install
    make install_sw

    cp -af /usr/local/lib64/libssl.a /usr/local/lib
    cp -af /usr/local/lib64/libcrypto.a /usr/local/lib
    cp *.pc /usr/lib64/pkgconfig/

    progress "install $name $version successfully"
    exit 0
fi

current_version=`openssl version | awk '{print $2}'|head -n 1`
if [[ "$current_version" == "$version" ]]; then
progress "$name $current_version found, skip installing"
    exit 0
fi

fail "$name $current_version is not equal to dependent $version, please remove the old one and reinstall"
exit 1

