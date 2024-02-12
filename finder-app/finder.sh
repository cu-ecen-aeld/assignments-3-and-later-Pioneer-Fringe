#!/bin/sh

if [ $# -lt 2 ]
  then
    echo "Error: expect 2 parameters"
    exit 1
elif [ ! -d $1 ]
  then
    echo "Error: Invalid directory on filesystem"
    exit 1
else
    echo "The number of files are $(find $1 -type f | wc -l) and the number of matching lines are $(grep -r $2 $1 | wc -l)"
    exit 0
fi
