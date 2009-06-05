#! /bin/bash

# debug informations in log file, requires LogLevel debug in httpd.conf
#export CFLAGS=-DURL_ALIAS_DEBUG_ENABLED

APXS_PATH=`which apxs`

./autogen.sh \
&& ./configure --with-apxs=$APXS_PATH \
&& make \
&& sudo make install

echo "Build done, you can now restart Apache"