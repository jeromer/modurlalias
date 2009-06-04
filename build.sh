#! /bin/bash

# debug informations in log file, requires LogLevel debug in httpd.conf
#export CFLAGS=-DURL_ALIAS_DEBUG_ENABLED

APACHECTL_PATH=/usr/local/apache-2.2.9/bin/apachectl

echo "Done"
./autogen.sh \
&& ./configure --with-apxs=`which apxs` \
&& make \
&& sudo make install \
&& sudo ${APACHECTL_PATH} restart