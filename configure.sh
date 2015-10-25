#!/bin/sh

usage()
{
    cat <<EOF
Usage: $0 [OPTIONS]
    --help

    --app=NAME                  - binary file name
    --bin=PATH                  - path to install binary file.
                                  default value is /usr/bin/astra

    --with-modules=PATH[:PATH]  - list of modules (by default: *)
                                  * - include all modules from ./modules dir.
                                  For example, to append custom module, use:
                                  --with-modules=*:path/to/custom/module

    --with-ffdecsa              - build with ffdecsa
    --with-libdvbcsa-static     - link libdvbcsa statically
    --with-igmp-emulation       - build with igmp emulated multicast renew

    --cc=GCC                    - custom C compiler (cross-compile)
    --static                    - build static binary
    --arch=ARCH                 - CPU architecture type (by default: native)

    --debug                     - build version for debug

    --cflags="..."              - custom compiler flags
    --ldflags="..."             - custom linker flags
EOF
    exit 0
}

SRCDIR=`dirname $0`

MAKEFILE="Makefile"
CONFIG_FILE="config.h"
MODULES_FILE="modules.h"

APP="astra"
APP_C="gcc"
APP_STRIP="strip"
APP_OBJCOPY="objcopy"

APP_STRIP_ARGS="--strip-debug --strip-unneeded"

#     _    ____   ____
#    / \  |  _ \ / ___|
#   / _ \ | |_) | |  _
#  / ___ \|  _ <| |_| |
# /_/   \_\_| \_\\____|
#

ARG_CC=0
ARG_BPATH="/usr/bin/$APP"
ARG_MODULES="*"
ARG_BUILD_STATIC=0
ARG_ARCH="native"
ARG_CFLAGS=""
ARG_LDFLAGS=""
ARG_FFDECSA=0
ARG_LIBDVBCSA_STATIC=0
ARG_IGMP_EMULATION=0
ARG_DEBUG=0

set_cc()
{
    ARG_CC=1
    APP_C="$1"
    APP_STRIP=`echo $1 | sed 's/gcc$/strip/'`
    APP_OBJCOPY=`echo $1 | sed 's/gcc$/objcopy/'`
}

while [ $# -ne 0 ] ; do
    OPT="$1"
    shift

    case "$OPT" in
        "--help")
            usage
            ;;
        "--app="*)
            APP=`echo $OPT | sed -e 's/^[a-z-]*=//'`
            ;;
        "--bin="*)
            ARG_BPATH=`echo $OPT | sed -e 's/^[a-z-]*=//'`
            ;;
        "--with-modules="*)
            ARG_MODULES=`echo $OPT | sed -e 's/^[a-z-]*=//'`
            ;;
        "--with-ffdecsa")
            ARG_FFDECSA=1
            ;;
        "--with-libdvbcsa-static")
            ARG_LIBDVBCSA_STATIC=1
            ;;
        "--with-igmp-emulation")
            ARG_IGMP_EMULATION=1
            ;;
        "--cc="*)
            set_cc `echo $OPT | sed 's/^--cc=//'`
            ;;
        "--static")
            ARG_BUILD_STATIC=1
            ;;
        "--build-static")
            ARG_BUILD_STATIC=1
            ;;
        "--arch="*)
            ARG_ARCH=`echo $OPT | sed -e 's/^[a-z-]*=//'`
            ;;
        "--cflags="*)
            ARG_CFLAGS=`echo $OPT | sed -e 's/^[a-z-]*=//'`
            ;;
        "--ldflags="*)
            ARG_LDFLAGS=`echo $OPT | sed -e 's/^[a-z-]*=//'`
            ;;
        "--debug")
            ARG_DEBUG=1
            ;;
        "CFLAGS="*)
            ARG_CFLAGS=`echo $OPT | sed -e 's/^[A-Z]*=//'`
            ;;
        "LDFLAGS="*)
            ARG_LDFLAGS=`echo $OPT | sed -e 's/^[A-Z]*=//'`
            ;;
        *)
            echo "Unknown option: $OPT"
            echo "For more information see: $0 --help"
            exit 1
            ;;
    esac
done

if ! which $APP_C >/dev/null ; then
    echo "C Compiler is not found :$APP_C"
    exit 1
fi

if test -f $MAKEFILE ; then
    echo "Cleaning previous build..." >&2
    make clean
    echo >&2
fi

rm -f $CONFIG_FILE
touch $CONFIG_FILE
rm -f $MODULES_FILE
touch $MODULES_FILE

CFLAGS="-O2 -fomit-frame-pointer -g -I$SRCDIR -Wall -Wextra -Wshadow -Wstrict-prototypes -pedantic -fno-builtin -std=iso9899:1999 -D_GNU_SOURCE"

if [ -n "$ARG_CFLAGS" ] ; then
    CFLAGS="$CFLAGS $ARG_CFLAGS"
fi

if [ $ARG_DEBUG -eq 1 ] ; then
    APP_STRIP=":"
fi

#   ____ ____  _   _
#  / ___|  _ \| | | |
# | |   | |_) | | | |
# | |___|  __/| |_| |
#  \____|_|    \___/
#

MACHINE=`$APP_C -dumpmachine`
ARCH=`echo $MACHINE | sed "s|-.*\$||"`

#     _    ____   ____ _   _
#    / \  |  _ \ / ___| | | |
#   / _ \ | |_) | |   | |_| |
#  / ___ \|  _ <| |___|  _  |
# /_/   \_\_| \_\\____|_| |_|
#

$APP_C $CFLAGS -march=$ARG_ARCH -E -x c /dev/null >/dev/null 2>&1
if [ $? -eq 0 ] ; then
    CFLAGS="$CFLAGS -march=$ARG_ARCH"
else
    echo "Error: gcc does not support -march=$ARG_ARCH" >&2
fi

case "$MACHINE" in
*"android"*)
    OS="android"
    CFLAGS="$CFLAGS -DWITH_EPOLL"
    LDFLAGS="-ldl -lm"
    ;;
*"linux"*)
    OS="linux"
    CFLAGS="$CFLAGS -pthread -DWITH_EPOLL"
    if $APP_C $CFLAGS -dM -E -xc /dev/null | grep -q "__i386__" ; then
        CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64"
    fi
    LDFLAGS="-ldl -lm -lpthread -lrt"
    ;;
*"freebsd"*)
    OS="freebsd"
    CFLAGS="$CFLAGS -pthread -DWITH_KQUEUE"
    LDFLAGS="-lm -lpthread"
    APP_STRIP_ARGS=""
    APP_OBJCOPY=":"
    ;;
*"darwin"*)
    OS="darwin"
    CFLAGS="$CFLAGS -pthread -DWITH_KQUEUE"
    LDFLAGS=""
    APP_STRIP_ARGS=""
    APP_OBJCOPY=":"
    ;;
*"mingw"*)
    OS="mingw"
    CFLAGS="$CFLAGS -DWITH_SELECT"
    APP="$APP.exe"
    WS32=`$APP_C -print-file-name=libws2_32.a`
    LDFLAGS="$WS32"
    ;;
*)
    echo "Unknown machine type \"$MACHINE\""
    exit 1
    ;;
esac

if [ $ARG_BUILD_STATIC -eq 1 ] ; then
    LDFLAGS="$LDFLAGS -static"
fi

if [ -n "$ARG_LDFLAGS" ] ; then
    LDFLAGS="$LDFLAGS $ARG_LDFLAGS"
fi

#  ____ ____  _____
# / ___/ ___|| ____|
# \___ \___ \|  _|
#  ___) |__) | |___
# |____/____/|_____|
#

APP_SSE=0

sse_test_c()
{
    cat <<EOF
#include <stdio.h>
#include <emmintrin.h>
int main(void) { return 0; }
EOF
}

check_sse()
{
    RET=1

    sse_test_c | $APP_C -Werror $CFLAGS -c -o .link-test.o -x c - >/dev/null 2>&1
    if [ $? -eq 0 ] ; then
        $APP_C $LDFLAGS .link-test.o -o .link-test >/dev/null 2>&1
        if [ $? -eq 0 ] ; then
            RET=0
        fi
    fi

    rm -f .link-test.o .link-test
    return $RET
}

if echo "$ARCH" | grep -q "i[3-6]86\|x86_64" ; then
    $APP_C $CFLAGS -msse -E -x c /dev/null >/dev/null 2>&1
    if [ $? -eq 0 ] ; then
        CFLAGS="$CFLAGS -msse"
        $APP_C $CFLAGS -msse2 -E -x c /dev/null >/dev/null 2>&1
        if [ $? -eq 0 ] ; then
            CFLAGS="$CFLAGS -msse2"
            $APP_C $CFLAGS -msse4 -E -x c /dev/null >/dev/null 2>&1
            if [ $? -eq 0 ] ; then
                CFLAGS="$CFLAGS -msse4"
            fi
        fi

        if check_sse ; then
            APP_SSE=1
        fi
    fi
fi

#  _     ___ ____  ______     ______   ____ ____    _
# | |   |_ _| __ )|  _ \ \   / / __ ) / ___/ ___|  / \
# | |    | ||  _ \| | | \ \ / /|  _ \| |   \___ \ / _ \
# | |___ | || |_) | |_| |\ V / | |_) | |___ ___) / ___ \
# |_____|___|____/|____/  \_/  |____/ \____|____/_/   \_\
#

APP_HAVE_LIBDVBCSA=0

libdvbcsa_test_c()
{
    cat <<EOF
#include <dvbcsa/dvbcsa.h>
int main(void) {
    struct dvbcsa_key_s *key = dvbcsa_key_alloc();
    dvbcsa_key_free(key);
    return 0;
}
EOF
}

check_libdvbcsa()
{
    RET=1

    libdvbcsa_test_c | $APP_C -Werror $1 -Wno-strict-prototypes -c -o .link-test.o -x c - >/dev/null 2>&1
    if [ $? -eq 0 ] ; then
        $APP_C .link-test.o -o .link-test $2 >/dev/null 2>&1
        if [ $? -eq 0 ] ; then
            RET=0
        fi
    fi

    rm -f .link-test.o .link-test
    return $RET
}

build_libdvbcsa()
{
    if [ $APP_SSE -ne 0 ] ; then
        echo "Build libdvbcsa with SSE"
        $SRCDIR/contrib/libdvbcsa.sh SSE $APP_C
        return $?
    else
        echo "Build libdvbcsa with UINT32"
        $SRCDIR/contrib/libdvbcsa.sh UINT32 $APP_C
        return $?
    fi
}

check_libdvbcsa_all()
{
    if check_libdvbcsa "$CFLAGS" "$LDFLAGS" ; then
        APP_HAVE_LIBDVBCSA=1
        return 0
    fi

    if [ "$ARG_LIBDVBCSA_STATIC" -ne 1 ] ; then
        LIBDVBCSA_LDFLAGS="-ldvbcsa"
        if check_libdvbcsa "" "$LIBDVBCSA_LDFLAGS" ; then
            APP_HAVE_LIBDVBCSA=2
            LDFLAGS="$LDFLAGS $LIBDVBCSA_LDFLAGS"
            return 0
        fi
    fi

    if ! build_libdvbcsa ; then
        return 1
    fi

    LIBDVBCSA_CFLAGS="-I$SRCDIR/contrib/build/libdvbcsa/src"
    LIBDVBCSA_LDFLAGS="$SRCDIR/contrib/build/libdvbcsa/libdvbcsa.a"
    if check_libdvbcsa "$LIBDVBCSA_CFLAGS" "$LIBDVBCSA_LDFLAGS" ; then
        APP_HAVE_LIBDVBCSA=3
        CFLAGS="$CFLAGS $LIBDVBCSA_CFLAGS"
        LDFLAGS="$LDFLAGS $LIBDVBCSA_LDFLAGS"
        return 0
    fi

    return 1
}

check_libdvbcsa_all

#       _            _                   _   _   _
#   ___| | ___   ___| | __     __ _  ___| |_| |_(_)_ __ ___   ___
#  / __| |/ _ \ / __| |/ /    / _` |/ _ \ __| __| | '_ ` _ \ / _ \
# | (__| | (_) | (__|   <    | (_| |  __/ |_| |_| | | | | | |  __/
#  \___|_|\___/ \___|_|\_\____\__, |\___|\__|\__|_|_| |_| |_|\___|
#                       |_____|___/

clock_gettime_test_c()
{
    cat <<EOF
#include <time.h>
int main(void) {
    struct timespec ts;
    return clock_gettime(CLOCK_REALTIME, &ts);
}
EOF
}

check_clock_gettime()
{
    clock_gettime_test_c | $APP_C -Werror $CFLAGS -c -o /dev/null -x c - >/dev/null 2>&1
}

APP_HAVE_CLOCK_GETTIME=0
if check_clock_gettime ; then
    APP_HAVE_CLOCK_GETTIME=1
fi

#  ____   ____ _____ ____
# / ___| / ___|_   _|  _ \
# \___ \| |     | | | |_) |
#  ___) | |___  | | |  __/
# |____/ \____| |_| |_|
#

sctp_h_test_c()
{
    cat <<EOF
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
int main(void) { return 0; }
EOF
}

check_sctp_h()
{
    sctp_h_test_c | $APP_C -Werror $CFLAGS -o /dev/null -x c - >/dev/null 2>&1
}

APP_HAVE_NETINET_SCTP_H=0
if check_sctp_h ; then
    APP_HAVE_NETINET_SCTP_H=1
fi

#  _____           _ _
# | ____|_ __   __| (_) __ _ _ __
# |  _| | '_ \ / _` | |/ _` | '_ \
# | |___| | | | (_| | | (_| | | | |
# |_____|_| |_|\__,_|_|\__,_|_| |_|
#

endian_h_test_c()
{
    cat <<EOF
#include <endian.h>
#ifndef __BYTE_ORDER
#error "__BYTE_ORDER not defined"
#endif
int main(void) { return 0; }
EOF
}

check_endian_h()
{
    endian_h_test_c | $APP_C -Werror $CFLAGS -c -o /dev/null -x c - >/dev/null 2>&1
}

APP_HAVE_ENDIAN_H=0
if check_endian_h ; then
    APP_HAVE_ENDIAN_H=1
fi

#                           _
#  _ __  _ __ ___  __ _  __| |
# | '_ \| '__/ _ \/ _` |/ _` |
# | |_) | | |  __/ (_| | (_| |
# | .__/|_|  \___|\__,_|\__,_|
# |_|

pread_test_c()
{
    cat <<EOF
#include <unistd.h>
int main(void) { char b[256]; return pread(0, b, sizeof(b), 0); }
EOF
}

check_pread()
{
    pread_test_c | $APP_C -Werror $CFLAGS -c -o /dev/null -x c - >/dev/null 2>&1
}

APP_HAVE_PREAD=0
if check_pread ; then
    APP_HAVE_PREAD=1
fi

#      _                  _
#  ___| |_ _ __ _ __   __| |_   _ _ __
# / __| __| '__| '_ \ / _` | | | | '_ \
# \__ \ |_| |  | | | | (_| | |_| | |_) |
# |___/\__|_|  |_| |_|\__,_|\__,_| .__/
#                                |_|

strndup_test_c()
{
    cat <<EOF
#include <string.h>
int main(void) { return (strndup("test", 2) != NULL) ? 0 : 1; }
EOF
}

check_strndup()
{
    strndup_test_c | $APP_C -Werror $CFLAGS -c -o /dev/null -x c - >/dev/null 2>&1
}

APP_HAVE_STRNDUP=0
if check_strndup ; then
    APP_HAVE_STRNDUP=1
fi

#      _              _
#  ___| |_ _ __ _ __ | | ___ _ __
# / __| __| '__| '_ \| |/ _ \ '_ \
# \__ \ |_| |  | | | | |  __/ | | |
# |___/\__|_|  |_| |_|_|\___|_| |_|
#

strnlen_test_c()
{
    cat <<EOF
#include <string.h>
int main(void) { return (strnlen("test", 2) == 4) ? 0 : 1; }
EOF
}

check_strnlen()
{
    strnlen_test_c | $APP_C -Werror $CFLAGS -c -o /dev/null -x c - >/dev/null 2>&1
}

APP_HAVE_STRNLEN=0
if check_strnlen ; then
    APP_HAVE_STRNLEN=1
fi

#                  _                                         _ _
#  _ __   ___  ___(_)_  __    _ __ ___   ___ _ __ ___   __ _| (_) __ _ _ __
# | '_ \ / _ \/ __| \ \/ /   | '_ ` _ \ / _ \ '_ ` _ \ / _` | | |/ _` | '_ \
# | |_) | (_) \__ \ |>  <    | | | | | |  __/ | | | | | (_| | | | (_| | | | |
# | .__/ \___/|___/_/_/\_\___|_| |_| |_|\___|_| |_| |_|\__,_|_|_|\__, |_| |_|
# |_|                   |_____|                                  |___/

posix_memalign_test_c()
{
    cat <<EOF
#include <stdio.h>
#include <stdlib.h>
int main(void) { void *p = NULL; return posix_memalign(&p, 32, 128); }
EOF
}

check_posix_memalign()
{
    posix_memalign_test_c | $APP_C -Werror $CFLAGS $APP_CFLAGS -o /dev/null -x c - >/dev/null 2>&1
}

APP_HAVE_POSIX_MEMALIGN=0
if check_posix_memalign ; then
    APP_HAVE_POSIX_MEMALIGN=1
fi

#        _
#   __ _(_) ___
#  / _` | |/ _ \
# | (_| | | (_) |
#  \__,_|_|\___/
#

aio_test_c()
{
    cat <<EOF
#ifdef _WIN32
#   error Win32
#endif
#include <aio.h>
int main(void) { return 0; }
EOF
}

check_aio()
{
    aio_test_c | $APP_C -Werror $CFLAGS $APP_CFLAGS -o /dev/null -x c - >/dev/null 2>&1
}

#  _ _ _           _
# | (_) |__   __ _(_) ___
# | | | '_ \ / _` | |/ _ \
# | | | |_) | (_| | | (_) |
# |_|_|_.__/ \__,_|_|\___/
#

libaio_test_c()
{
    cat <<EOF
#include <libaio.h>
int main(void) { return 0; }
EOF
}

check_libaio()
{
    libaio_test_c | $APP_C -Werror $CFLAGS $APP_CFLAGS -o /dev/null -x c - >/dev/null 2>&1
}

APP_HAVE_AIO=0
APP_HAVE_LIBAIO=0

if check_aio ; then
    APP_HAVE_AIO=1
    if [ "$OS" = "linux" ] ; then
        if check_libaio ; then
            APP_HAVE_LIBAIO=1
            LDFLAGS="$LDFLAGS -laio"
        fi
    fi
fi

#             _   _  __           _     _
#   __ _  ___| |_(_)/ _| __ _  __| | __| |_ __ ___
#  / _` |/ _ \ __| | |_ / _` |/ _` |/ _` | '__/ __|
# | (_| |  __/ |_| |  _| (_| | (_| | (_| | |  \__ \
#  \__, |\___|\__|_|_|  \__,_|\__,_|\__,_|_|  |___/
#  |___/

getifaddrs_test_c()
{
    cat <<EOF
#include <stdio.h>
#include <sys/types.h>
#include <ifaddrs.h>
int main(void) {
    struct ifaddrs *ifaddr;
    const int s = getifaddrs(&ifaddr);
    freeifaddrs(ifaddr);
    return s;
}
EOF
}

check_getifaddrs()
{
    getifaddrs_test_c | $APP_C -Werror $CFLAGS $APP_CFLAGS -c -o /dev/null -x c - >/dev/null 2>&1
}

APP_HAVE_GETIFADDRS=0
if check_getifaddrs ; then
    APP_HAVE_GETIFADDRS=1
fi


#                   __ _         _
#   ___ ___  _ __  / _(_) __ _  | |__
#  / __/ _ \| '_ \| |_| |/ _` | | '_ \
# | (_| (_) | | | |  _| | (_| |_| | | |
#  \___\___/|_| |_|_| |_|\__, (_)_| |_|
#                        |___/

exec 6>$CONFIG_FILE

cat >&6 <<EOF
/* generated by configure.sh */

#ifndef _ASC_CONFIG_H_
#define _ASC_CONFIG_H_ 1

#define APP_OS "$OS"
EOF

if [ $APP_SSE -ne 0 ] ; then
    echo "#define APP_SSE 1" >&6
    echo "#define HAVE_EMMINTRIN_H 1" >&6
fi

if [ $APP_HAVE_CLOCK_GETTIME -ne 0 ] ; then
    echo "#define HAVE_CLOCK_GETTIME 1" >&6
fi

if [ $APP_HAVE_NETINET_SCTP_H -ne 0 ] ; then
    echo "#define HAVE_NETINET_SCTP_H 1" >&6
fi

if [ $APP_HAVE_ENDIAN_H -ne 0 ] ; then
    echo "#define HAVE_ENDIAN_H 1" >&6
fi

if [ $APP_HAVE_PREAD -ne 0 ] ; then
    echo "#define HAVE_PREAD 1" >&6
fi

if [ $APP_HAVE_STRNDUP -ne 0 ] ; then
    echo "#define HAVE_STRNDUP 1" >&6
fi

if [ $APP_HAVE_STRNLEN -ne 0 ] ; then
    echo "#define HAVE_STRNLEN 1" >&6
fi

if [ $ARG_IGMP_EMULATION -ne 0 ] ; then
    echo "#define IGMP_EMULATION 1" >&6
fi

if [ $APP_HAVE_POSIX_MEMALIGN -ne 0 ] ; then
    echo "#define HAVE_POSIX_MEMALIGN 1" >&6
fi

if [ $APP_HAVE_AIO -ne 0 ] ; then
    echo "#define HAVE_AIO 1" >&6
fi

if [ $APP_HAVE_LIBAIO -ne 0 ] ; then
    echo "#define HAVE_LIBAIO 1" >&6
fi

if [ $APP_HAVE_GETIFADDRS -ne 0 ] ; then
    echo "#define HAVE_GETIFADDRS 1" >&6
fi

if [ $ARG_FFDECSA -ne 0 ] ; then
    echo "#define HAVE_FFDECSA 1" >&6
    if [ $APP_SSE -eq 1 ] ; then
        echo "#define PARALLEL_MODE 1286" >&6
    else
        echo "#define PARALLEL_MODE 642" >&6
    fi
fi

if [ $APP_HAVE_LIBDVBCSA -ne 0 ] ; then
    echo "#define HAVE_LIBDVBCSA 1" >&6
    echo "#define LIBDVBCSA_MODE $APP_HAVE_LIBDVBCSA" >&6
fi

cat >&6 <<EOF

#endif /* _ASC_CONFIG_H_ */
EOF

exec 6>&-

#  _____ _
# |  ___| | __ _  __ _ ___
# | |_  | |/ _` |/ _` / __|
# |  _| | | (_| | (_| \__ \
# |_|   |_|\__,_|\__, |___/
#                |___/

APP_CFLAGS="$CFLAGS"
APP_LDFLAGS="$LDFLAGS"

# temporary file

TMP_MODULE_MK="/tmp"
if [ ! -d "/tmp" ] ; then
    TMP_MODULE_MK="."
fi
TMP_MODULE_MK="$TMP_MODULE_MK/$APP_module.mk-$RANDOM"
touch $TMP_MODULE_MK 2>/dev/null
if [ $? -ne 0 ] ; then
    echo "ERROR: failed to build tmp file ($TMP_MODULE_MK)"
    exit 1
fi
rm -f $TMP_MODULE_MK

#

cat >&2 <<EOF
Compiler Flags:
  TARGET: $MACHINE
      CC: $APP_C
  CFLAGS: $APP_CFLAGS

EOF

#  __  __       _         __ _ _
# |  \/  | __ _| | _____ / _(_) | ___
# | |\/| |/ _` | |/ / _ \ |_| | |/ _ \
# | |  | | (_| |   <  __/  _| | |  __/
# |_|  |_|\__,_|_|\_\___|_| |_|_|\___|

rm -f $MAKEFILE
exec 5>$MAKEFILE

cat >&5 <<EOF
# generated by configure.sh

MAKEFLAGS = -rR --no-print-directory

APP         = $APP
CC          = $APP_C
CFLAGS      = $APP_CFLAGS
OS          = $OS

CORE_OBJS   =
MODS_OBJS   =

.PHONY: all clean distclean
all: \$(APP)

clean: \$(APP)-clean
	@rm -f Makefile config.h modules.h modules/inscript/inscript.h

distclean: clean
EOF

echo "Check modules:" >&2

#                  _
#  _ __ ___   __ _(_)_ __    ___
# | '_ ` _ \ / _` | | '_ \  / __|
# | | | | | | (_| | | | | || (__
# |_| |_| |_|\__,_|_|_| |_(_)___|

APP_SOURCE="$SRCDIR/main.c"
APP_OBJS=""

__check_main_app()
{
    APP_OBJS="main.o"
    $APP_C $APP_CFLAGS -MT $APP_OBJS -MM $APP_SOURCE 2>$TMP_MODULE_MK
    if [ $? -ne 0 ] ; then
        return 1
    fi
    cat <<EOF
	@echo "   CC: \$@"
	@\$(CC) \$(CFLAGS) -o \$@ -c \$<
EOF

    return 0
}

__check_main_app >&5
if [ $? -ne 0 ] ; then
    echo "  ERROR: $APP_SOURCE" >&2
    if [ -f $TMP_MODULE_MK ] ; then
        cat $TMP_MODULE_MK >&2
        rm -f $TMP_MODULE_MK
    fi
    exec 5>&-
    exit 1
else
    echo "     OK: $APP_SOURCE"
fi
echo "" >&5

#                      _       _                  _
#  _ __ ___   ___   __| |_   _| | ___   _ __ ___ | | __
# | '_ ` _ \ / _ \ / _` | | | | |/ _ \ | '_ ` _ \| |/ /
# | | | | | | (_) | (_| | |_| | |  __/_| | | | | |   <
# |_| |_| |_|\___/ \__,_|\__,_|_|\___(_)_| |_| |_|_|\_\

select_modules()
{
    echo "$ARG_MODULES" | tr ':' '\n' | while read M ; do
        if [ -z "$M" ] ; then
            :
        elif [ "$M" = "*" ] ; then
            ls -d $SRCDIR/modules/* | while read M ; do
                if [ -f "$M/module.mk" ] ; then
                    echo "$M"
                fi
            done
        else
            echo "$M" | sed 's/\/$//'
        fi
    done
}

APP_MODULES_LIST=`select_modules`

# modules checking

APP_MODULES_CONF=""

__check_module()
{
    MODULE="$1"
    OGROUP="$2"

    SOURCES=""
    MODULES=""
    CFLAGS=""
    LDFLAGS=""
    ERROR=""

    OBJECTS=""

    . $MODULE/module.mk

    if [ -n "$ERROR" ] ; then
        echo "$MODULE: error: $ERROR" >$TMP_MODULE_MK
        return 1
    fi

    if [ -n "$LDFLAGS" ] ; then
        APP_LDFLAGS="$APP_LDFLAGS $LDFLAGS"
    fi

    if [ -z "$SOURCES" ] ; then
        echo "$MODULE: SOURCES is not defined" >$TMP_MODULE_MK
        return 1
    fi

    echo "${MODULE}_CFLAGS = $CFLAGS"
    echo ""

    for S in $SOURCES ; do
        O=`echo $S | sed -e 's/.c$/.o/'`
        OBJECTS="$OBJECTS $MODULE/$O"
        $APP_C $APP_CFLAGS $CFLAGS -MT $MODULE/$O -MM $MODULE/$S 2>$TMP_MODULE_MK
        if [ $? -ne 0 ] ; then
            return 1
        fi
        cat <<EOF
	@echo "   CC: \$@"
	@\$(CC) \$(CFLAGS) \$(${MODULE}_CFLAGS) -o \$@ -c \$<
EOF
    done

    cat <<EOF

${MODULE}_OBJECTS = $OBJECTS
${OGROUP} += \$(${MODULE}_OBJECTS)

EOF

    if [ -n "MODULES" ] ; then
        APP_MODULES_CONF="$APP_MODULES_CONF $MODULES"
    fi

    return 0
}

check_module()
{
    MODULE="$1"
    OGROUP="$2"

    __check_module $MODULE $OGROUP >&5
    if [ $? -eq 0 ] ; then
        echo "     OK: $MODULE" >&2
    else
        echo "   SKIP: $MODULE" >&2
    fi
    if [ -f $TMP_MODULE_MK ] ; then
        cat $TMP_MODULE_MK >&2
        rm -f $TMP_MODULE_MK
    fi
}

#   ____
#  / ___|___  _ __ ___
# | |   / _ \| '__/ _ \
# | |__| (_) | | |  __/
#  \____\___/|_|  \___|

check_module $SRCDIR/core "CORE_OBJS"
check_module $SRCDIR/lua "CORE_OBJS"

#  __  __           _       _
# |  \/  | ___   __| |_   _| | ___  ___
# | |\/| |/ _ \ / _` | | | | |/ _ \/ __|
# | |  | | (_) | (_| | |_| | |  __/\__ \
# |_|  |_|\___/ \__,_|\__,_|_|\___||___/

for M in $APP_MODULES_LIST ; do
    check_module $M "MODS_OBJS"
done

#                      _       _             _
#  _ __ ___   ___   __| |_   _| | ___  ___  | |__
# | '_ ` _ \ / _ \ / _` | | | | |/ _ \/ __| | '_ \
# | | | | | | (_) | (_| | |_| | |  __/\__ \_| | | |
# |_| |_| |_|\___/ \__,_|\__,_|_|\___||___(_)_| |_|
#

rm -f $MODULES_FILE
exec 6>$MODULES_FILE

cat >&6 <<EOF
/* generated by configure.sh */

#ifndef _ASC_MODULES_H_
#define _ASC_MODULES_H_ 1

#include <core/lua.h>

EOF

for M in $APP_MODULES_CONF ; do
    echo "extern const asc_module_t asc_module_$M;" >&6
done

cat >&6 <<EOF

static const asc_module_t *asc_modules[] =
{
EOF

for M in $APP_MODULES_CONF ; do
    echo "    &asc_module_$M," >&6
done

cat >&6 <<EOF
};

#endif /* _ASC_MODULES_H_ */
EOF

exec 6>&-

#  _     _       _
# | |   (_)_ __ | | __
# | |   | | '_ \| |/ /
# | |___| | | | |   <
# |_____|_|_| |_|_|\_\

VERSION_MAJOR=`sed -n 's/.*ASTRA_VERSION_MAJOR \([0-9]*\).*/\1/p' version.h`
VERSION_MINOR=`sed -n 's/.*ASTRA_VERSION_MINOR \([0-9]*\).*/\1/p' version.h`
VERSION="$VERSION_MAJOR.$VERSION_MINOR"

cat >&2 <<EOF

Linker Flags:
 VERSION: $VERSION
     OUT: $APP
 LDFLAGS: $APP_LDFLAGS

Install Path:
  BINARY: $ARG_BPATH
EOF

cat >&5 <<EOF
LD          = $APP_C
LDFLAGS     = $APP_LDFLAGS
STRIP       = $APP_STRIP
OBJCOPY     = $APP_OBJCOPY
VERSION     = $VERSION
BPATH       = $ARG_BPATH

\$(APP): $APP_OBJS \$(CORE_OBJS) \$(MODS_OBJS)
	@echo "BUILD: \$@"
	@\$(LD) \$^ -o \$@ \$(LDFLAGS)
	@\$(OBJCOPY) --only-keep-debug \$@ \$@.debug
	@\$(STRIP) $APP_STRIP_ARGS \$@

install: \$(APP)
	@echo "INSTALL: \$(BPATH)"
	@rm -f \$(BPATH)
	@cp \$(APP) \$(BPATH)

uninstall:
	@echo "UNINSTALL: \$(APP)"
	@rm -f \$(BPATH)

\$(APP)-clean:
	@echo "CLEAN: \$(APP)"
	@rm -f \$(APP) \$(APP).debug $APP_OBJS
	@rm -f \$(MODS_OBJS)
	@rm -f \$(CORE_OBJS)
EOF

exec 5>&-
