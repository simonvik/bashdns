#!/bin/bash

if [ -z "$1" ];
then
	echo "Usage: ./bashdnsparser.sh DNSMSG"
	exit
fi

if [ -z "$2" ];
then
	MSG="$1"
else
	# Hack to remove the first bytes when its TCP
	MSG="${1:4:${#1}}"
fi

OFFSET=0


parse_hostname () {
	COMPRESSED=
	OLDOFFSET=
	HN=

	while true;
	do
		C=${MSG:$OFFSET:2}
		OFFSET=$((OFFSET+2))

		if [ $(( 16#$C & 0xc0 )) -eq $((0xc0)) ];
		then
			if [ -z "$COMPRESSED" ];
			then
				OLDOFFSET=$OFFSET
				COMPRESSED="true"
			fi
			D=${MSG:$OFFSET:2}
			OFFSET=$((((((16#$C) ^ 0xc0) << 8) | (16#$D))*2))
		else
			if [ $(( 16#$C )) -eq $((0x00)) ];
			then
				if [ -z "$HN" ];
				then
					HN="."
				fi
				break
			fi;

			for _ in $(eval echo "{0..$(( 16#$C -1))}");
			do
				CH=${MSG:$OFFSET:2}
				OFFSET=$((OFFSET+2))

				# shellcheck disable=SC2059
				HN="$HN$(printf "\x$CH")"
			done
			HN="$HN."
		fi;

	done

	# shellcheck disable=SC2236
	if [ ! -z $COMPRESSED ];
	then
		OFFSET=$((OLDOFFSET+2))
	fi

	echo -n "$HN"
}

parse_class() {
	case $(( 16#$1 )) in
	"1")
		echo -n "IN"
	;;
	"3")
		echo -n "CH"
	;;
	"4")
		echo -n "HS"
	;;
	"254")
		echo -n "NONE"
	;;
	"255")
		echo -n "ANY"
	;;
	esac
}

parse_rr() {
	# HOSTNAME
	parse_hostname

	# QTYPE
	RRTYPE=${MSG:$OFFSET:4}
	OFFSET=$((OFFSET+4))

	# QCLASS
	RRCLASS=${MSG:$OFFSET:4}
	OFFSET=$((OFFSET+4))

	# TTL
	TTL=${MSG:$OFFSET:8}
	OFFSET=$((OFFSET+8))

	# MSG LENGTH
	LENGTH=${MSG:$OFFSET:4}
	OFFSET=$((OFFSET+4))

	echo -n " $(( 16#$TTL )) "

	# This will print for example "IN"
	echo -n " $(parse_class "$RRCLASS") "

	case $(( 16#$RRTYPE )) in
	"1")
		echo "A $(( 16#${MSG:$OFFSET:2} )).$(( 16#${MSG:$OFFSET+2:2} )).$(( 16#${MSG:$OFFSET+4:2} )).$(( 16#${MSG:$OFFSET+6:2} ))"
		OFFSET=$((OFFSET+8))
	;;
	"2")
		echo -n "NS "
		parse_hostname
		echo
	;;
	"5")
		echo "CNAME "
		parse_hostname
		echo
		;;
	"6")
		echo -n "SOA "
		parse_hostname
		echo -n " "
		parse_hostname

		SERIAL=${MSG:$OFFSET:8}
		OFFSET=$((OFFSET+8))

		REFRESH=${MSG:$OFFSET:8}
		OFFSET=$((OFFSET+8))

		RETRY=${MSG:$OFFSET:8}
		OFFSET=$((OFFSET+8))

		EXPIRE=${MSG:$OFFSET:8}
		OFFSET=$((OFFSET+8))

		MINIMUM=${MSG:$OFFSET:8}
		OFFSET=$((OFFSET+8))
		echo " $(( 16#$SERIAL )) $(( 16#$REFRESH )) $(( 16#$RETRY )) $(( 16#$EXPIRE )) $(( 16#$MINIMUM)) "
	;;
	"15")
		PREF=${MSG:$OFFSET:4}
		OFFSET=$((OFFSET+4))
		echo -n "MX $(( 16#$PREF )) "
		parse_hostname
		echo
	;;
	"16")
		START_OFFSET=$OFFSET
		T=""
		while true;
		do
			L=${MSG:$OFFSET:2}

			if [ $OFFSET -eq $(( START_OFFSET + 16#$LENGTH * 2 )) ];
			then
				break;
			fi

			if [ $(( 16#$L )) -gt 0 ];
			then
				OFFSET=$((OFFSET+2))
				for _ in $(eval echo "{0..$(( 16#$L -1))}");
				do
					CH=${MSG:$OFFSET:2}
					OFFSET=$((OFFSET+2))

					# shellcheck disable=SC2059
					T="$T$(printf "\x$CH")"
				done
			fi
		done;
		echo "TXT $T"

	;;
	"28")
		AAAA=${MSG:$OFFSET:32}
		OFFSET=$((OFFSET+32))
		echo "AAAA ${AAAA:0:4}:${AAAA:4:4}:${AAAA:8:4}:${AAAA:12:4}:${AAAA:16:4}:${AAAA:20:4}:${AAAA:24:4}:${AAAA:28:4}"
	;;
	*)
		echo "TYPE$(( 16#$RRTYPE )) \\# $(( 16#$LENGTH )) ${MSG:$OFFSET:$(( 16#$LENGTH ))*2}"
		OFFSET=$((OFFSET+$(( 16#$LENGTH ))*2))
	;;
	esac
}


# DNS HEADER
ID=${MSG:$OFFSET:4}
OFFSET=$((OFFSET+4))

FLAGS=${MSG:$OFFSET:4}
OFFSET=$((OFFSET+4))

OPCODE=$(( 16#$FLAGS >> 11 & 0xF ))
case "$OPCODE" in
"0")
	O="QUERY"
;;
"1")
	O="IQUERY"
;;
"2")
	O="STATUS"
;;
*)
	O="RESERVED"
;;
esac

RCODE=$(( 16#$FLAGS & 0xF ))
case "$RCODE" in
"0")
	R="NOERROR"
;;
"1")
	R="FORMERR"
;;
"2")
	R="SERVFAIL"
;;
"3")
	R="NXDOMAIN"
;;
"4")
	R="NOTIMP"
;;
"5")
	R="REFUSED"
;;
*)
	R="**SOMETHING IS BAD**"
;;
esac


echo ";; ->>HEADER<<- opcode: $O, status: $R, id: $(( 16#$ID ))"
echo -n ";; flags:"

if [ $(( 16#$FLAGS & 1 << 15 )) -gt 0 ];
then
	echo -n " qr"
fi

if [ $(( 16#$FLAGS & 1 << 10 )) -gt 0 ];
then
	echo -n " aa"
fi

if [ $(( 16#$FLAGS & 1 << 9 )) -gt 0 ];
then
	echo -n " tc"
fi

if [ $(( 16#$FLAGS & 1 << 8 )) -gt 0 ];
then
	echo -n " rd"
fi

if [ $(( 16#$FLAGS & 1 << 7 )) -gt 0 ];
then
	echo -n " ra"
fi

if [ $(( 16#$FLAGS & 1 << 5 )) -gt 0 ];
then
	echo -n " ad"
fi

if [ $(( 16#$FLAGS & 1 << 4 )) -gt 0 ];
then
	echo -n " cd"
fi


QUERYS=${MSG:$OFFSET:4}
OFFSET=$((OFFSET+4))

ANSWERS=${MSG:$OFFSET:4}
OFFSET=$((OFFSET+4))

AUTH=${MSG:$OFFSET:4}
OFFSET=$((OFFSET+4))

ADD=${MSG:$OFFSET:4}
OFFSET=$((OFFSET+4))

echo "; QUERY: $(( 16#$QUERYS )), ANSWER: $(( 16#$ANSWERS )), AUTHORITY: $(( 16#$AUTH )), ADDITIONAL: $(( 16#$ADD ))"


# PARSE QUERYS
echo -e "\n;; QUESTION SECTION:"
for _ in $(eval echo "{0..$(($(( 16#$QUERYS ))-1))}");
do
	parse_hostname

	# PARSE QTYPE
	QTYPE=${MSG:$OFFSET:4}
	OFFSET=$((OFFSET+4))

	# PARSE QCLASS
	QCLASS=${MSG:$OFFSET:4}
	OFFSET=$((OFFSET+4))

	echo -n " $(parse_class "$QCLASS") "

	case $(( 16#$QTYPE )) in
	"1")
		echo "A"
	;;
	"2")
		echo "NS"
	;;
	"5")
		echo "CNAME"
	;;
	"6")
		echo "SOA"
	;;
	"15")
		echo "MX"
	;;
	"16")
		echo "TXT"
	;;
	"28")
		echo "AAAA"
	;;
	"255")
		echo -n "ANY"
	;;
	*)
		echo -n " TYPE$(( 16#$QTYPE )) "
	;;
	esac
done


# PARSE ANSWERS

if [ $(( 16#$ANSWERS )) -gt 0 ];
then
	echo -e "\n\n;; ANSWER SECTION:"

	for _ in $(eval echo "{0..$(($(( 16#$ANSWERS ))-1 ))}");
	do
		parse_rr
	done
fi

if [ $(( 16#$AUTH )) -gt 0 ];
then
	echo -e "\n\n;;AUTHORITY SECTION:"
	for _ in $(eval echo "{0..$(($(( 16#$AUTH ))-1))}");
	do
		parse_rr
	done
fi

if [ $(( 16#$ADD )) -gt 0 ];
then

	echo -e "\n\n;; ADDITIONAL SECTION:"
	# PARSE ANSWERS
	for _ in $(eval echo "{0..$(($(( 16#$ADD ))-1))}");
	do
		parse_rr
	done
fi

echo
