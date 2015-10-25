
if [ $ARG_FFDECSA -eq 0 -a $APP_HAVE_LIBDVBCSA -eq 0 ] ; then
    ERROR="DVB-CSA is not found"
fi

SOURCES_CSA=""

if [ $ARG_FFDECSA -eq 1 ] ; then
    SOURCES_CSA="FFdecsa/FFdecsa.c"
fi

SOURCES_CAM="cam/cam.c cam/des.c cam/newcamd.c"
SOURCES_CAS="cas/base.c cas/bulcrypt.c cas/conax.c cas/cryptoworks.c cas/dgcrypt.c cas/dre.c cas/exset.c cas/griffin.c cas/irdeto.c cas/mediaguard.c cas/nagra.c cas/viaccess.c cas/videoguard.c"

MODULES="decrypt newcamd"

SOURCES="$SOURCES_CSA $SOURCES_CAM $SOURCES_CAS decrypt.c"
