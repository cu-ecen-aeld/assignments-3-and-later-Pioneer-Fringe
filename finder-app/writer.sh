if [ $# -lt 2 ]
  then
    echo "Error: expect 2 parameters"
    exit 1
else
    mkdir -p $(dirname $1)
    echo $2 > $1
    if [ $? -eq 0 ]
      then
        exit 0
    else
        echo "Error: file could not be created"
        exit 1
    fi
fi
