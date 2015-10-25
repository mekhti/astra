
SOURCES="crc32.c sha1.c base64.c md5.c rc4.c strhex.c"
SOURCES="$SOURCES astra.c log.c timer.c utils.c json.c iso8859.c"
MODULES="astra log timer utils json base64 sha1 md5 rc4 str2hex iso8859"

if [ "$OS" != "mingw" ] ; then
    SOURCES="$SOURCES pidfile.c"
    MODULES="$MODULES pidfile"
fi
