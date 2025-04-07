FIRST_NAME=$1
LAST_NAME=$2
SHOW=$3

if [ "$SHOW" = "true" ]; then
  echo "Hello, $FIRST_NAME $LAST_NAME"
else
  echo "please mark the show option"
fi

