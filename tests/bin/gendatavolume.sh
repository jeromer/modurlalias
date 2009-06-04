#! /bin/bash
#
# Generates the SQL scripts to load a predefined amount
# of rows in the URL alias table.
#
# The SQL scripts will be stored in $TARGET_DIR/load.$MAX.rows.sql
# so it is easy to find them in import them afterwards
#

MAX=$1
SQL_TRUNCATE="TRUNCATE TABLE urlalias;"
SQL_QUERY_START="INSERT INTO urlalias VALUES ("
SQL_QUERY_END=");"
TARGET_DIR="tests/mysql/volume"


if [ -z $MAX ]
then
    echo "${0} <row number : int>"
    echo "Example : ${0} 100"
    exit 1
fi

i=1
target="${TARGET_DIR}/load.${MAX}.rows.sql"
touch $target
echo ${SQL_TRUNCATE} >> $target

echo "Generating ${MAX} INSERT INTO SQL queries in ${target}"

while [ $i -le $MAX ]
do
    source="/path/to/url_${i}"
    redirect_to=NULL
    module="content"
    view="view.php"
    params="vm=full&coid=${i}"
    generic_route=0
    route_priority=NULL

    echo "${SQL_QUERY_START} '${source}', ${redirect_to}, '${module}', '${view}', '${params}', ${generic_route}, ${route_priority} ${SQL_QUERY_END}" >> $target

    i=$((i+1))
done

echo "Done"