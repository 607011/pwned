#!/usr/bin/bash

DOWNLOAD_DIR=downloaded
COOKIE_JAR=cookies.txt

mkdir -p $DOWNLOAD_DIR

function usage() {
  echo "Usage:"
  echo "  get-all.sh [<first index>] <last index>"
}

function save {
  echo $LAST_ID > .latest
}

function ctrl_c()
{
  save
  exit
}

function get_key() {
  local old_tty_settings=$(stty -g)
  stty -icanon time 0 min 0
  echo $(head -c1)
  stty "$old_tty_settings"
}

trap ctrl_c SIGINT

if [[ -n $1 && -n $2 ]]; then
  FROM=$1
  TO=$2
elif [[ -n $1 ]]; then
  FROM=`head -1 .latest`
  TO=$1
fi

if [[ -z $FROM || -z $TO ]]; then
  usage
  exit 1
fi

echo "You're about to download plaintext password files from hashes.org."
echo "Clean download directory before proceeding? (y/n)"
read -s -n 1 reply
if [[ "$reply" = "y" ]]; then
  echo "Deleting ..."
  rm "${DOWNLOAD_DIR}"/*.txt
fi

echo "Fetching cookies ..."
curl -sSI --cookie-jar $COOKIE_JAR "https://hashes.org/leaks.php" > /dev/null

LAST_ID=${FROM}

echo "Fetching password lists from ${FROM} to ${TO} ... (Press q to quit.)"
for ID in `seq ${FROM} ${TO}`; do
  echo -n " #${ID} ... "
  OUTPUT_FILE="${DOWNLOAD_DIR}/${ID}.txt"
  curl "https://hashes.org/download.php?type=found&hashlistId=${ID}" \
    -sS \
    --cookie-jar $COOKIE_JAR \
    -H "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0" \
    -H "Referer: https://hashes.org/" \
    -o "${OUTPUT_FILE}"
  CONTENTS=`head -1 "${OUTPUT_FILE}"`
  if [ "$CONTENTS" = "Invalid hashlist!" ]; then
    echo "INVALID"
    rm "${OUTPUT_FILE}"
  elif [ "$CONTENTS" = "Hashlist is deleted!" ]; then
    echo "DELETED"
    rm "${OUTPUT_FILE}"
  elif [ `stat -c%s ${OUTPUT_FILE}` -eq 0 ]; then
    echo "EMPTY"
    rm "${OUTPUT_FILE}"
  else
    echo "OK"
    LAST_ID=$ID
  fi
  if [ "$(get_key)" = "q" ]; then
    break
  fi
done

stty sane
save
