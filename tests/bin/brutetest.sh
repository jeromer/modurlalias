#! /bin/sh

# Launches $MAX launchtests.sh instance in background

MAX=$1
i=1

if [ -z $MAX ]
then
    echo "${0} <max : int>"
    echo "Example : ${0} 10"
    exit 1
fi

while [ $i -le $MAX ]
do
    time ./tests/bin/launchtest.sh --quiet&
    i=$((i+1))
done