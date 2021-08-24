#!/bin/bash

# Single query, stolen from dig
# ID: ff41 FLAGS 0120 QUESTIONS : 0001 NOTHING OF THE REST: 0000 0000 0000
# Who needs security anyway, just reuse that good ID

PREFIX="ff4101200001000000000000"
HOSTNAME="$1."

if [ -z $HOSTNAME ];
then
	echo "Usage: HOSTNAME TYPE (no trailing dot)"
	exit
fi

if [ -z $2 ];
then
	TYPE="A"
else
	TYPE="$2"
fi

O=""
for i in $(eval echo "{0..${#HOSTNAME}}");
do
	C=${HOSTNAME:$i:1}
	if [ "$C" = "." ];
	then
		O="$O$(printf "%02x" $((${#TMP} / 2 )))$TMP"
		TMP=""
		continue
	fi

	TMP="$TMP$(printf "%02x" "'$C")"
done;

# Append trailing 0
O="${O}00"

# A INET
T="0001"
case "$TYPE" in
"A")
	T="0001"
;;
"NS")
	T="0002"
;;
"CNAME")
	T="0005"
;;
"SOA")
	T="0006"
;;
"MX")
	T="000F"
;;
"TXT")
	T="0010"
;;
"AAAA")
	T="001C"
;;
"ANY")
	T="00FF"
;;
esac
O="${O}${T}0001"


S="$PREFIX$O"
# Prepend length of packge (TCP)
S="$(printf "%04x" $((${#S}/2)))$S"

exec 3</dev/tcp/1.1.1.1/53
SS=""
for i in $(eval echo "{0..$((${#S}-1))..2}");
do
	SS="$SS\x${S:$i:2}"
done

echo -e $SS >&3


#I HATE THIS
LC_ALL=
LC_CTYPE=
LANG=
IFS=

bash bashdnsparser.sh $(
while read -t 0.1 -d '' -n 1 b; do
	printf "%02x" "'$b"
done <&3
) "true"


