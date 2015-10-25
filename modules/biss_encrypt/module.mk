
if [ $APP_HAVE_LIBDVBCSA -eq 0 ] ; then
    ERROR="libdvbcsa is not found"
fi

SOURCES="biss_encrypt.c"
MODULES="biss_encrypt"
