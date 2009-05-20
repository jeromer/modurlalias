#! /bin/bash

set -e

HTTP_PROTOCOL="http"
HTTP_HOST="localhost"
HTTP_PATH="modurlalias"
HTTP_PORT="81"

MYSQL_HOST="localhost"
MYSQL_USER="root"
MYSQL_PASS="publish"
MYSQL_DB="modurlalias"
MYSQL_QUERY_NO_REGEX="SELECT useregex, source FROM urlalias WHERE useregex = 0 ORDER BY source";

URL_ALIAS_LIST_FILENAME="/tmp/urlaliaslist.txt"

BIN_MYSQL="$(which mysql)"
BIN_CURL="$(which curl)"
BIN_SED="$(which sed)"
BIN_CAT="$(which cat)"
BIN_CUT="$(which cut)"

CMD_MYSQL="${BIN_MYSQL} -h "${MYSQL_HOST}" -u "${MYSQL_USER}" -p"${MYSQL_PASS}" "${MYSQL_DB}""
CMD_CURL="${BIN_CURL} -s -X GET"

COLOR_GREEN="\033[32;01m"
COLOR_RED="\033[1;31m"
COLOR_WHITE="\033[37;01m"
COLOR_END="\033[00m"

success() {
    echo -e "[${COLOR_GREEN}SUCCESS${COLOR_END}]"
}

failed() {
    echo -e "[${COLOR_RED}FAILED${COLOR_END}]"
}

echo "Fetching test data ..."

if [ -e "${URL_ALIAS_LIST_FILENAME}" ]
then
    rm ${URL_ALIAS_LIST_FILENAME}
fi

# Fetching URL aliases
#
# The sed part removes the first line, which corresponds
# to the colum name in the query result
#
# The cut part remove the regex field
${CMD_MYSQL} -e "${MYSQL_QUERY_NO_REGEX}" | ${BIN_SED} 1d | ${BIN_CUT} -d '	' -f 2 > ${URL_ALIAS_LIST_FILENAME}

for url_alias in $(${BIN_CAT} ${URL_ALIAS_LIST_FILENAME})
do
    expected_result=${url_alias}
    curl_result="$(${CMD_CURL} ${HTTP_PROTOCOL}://${HTTP_HOST}:${HTTP_PORT}/${HTTP_PATH}/${url_alias})"
    echo -en "Testing URL alias ${COLOR_WHITE}${url_alias}${COLOR_END}  "

    if [ "$expected_result" == "$curl_result" ]
    then
        success
    else
        failed
    fi
done