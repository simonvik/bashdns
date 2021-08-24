# DNS msg parser in bash

Welcome to this stupid project that implements a DNS parser in pure? bash

The code is *very* unsafe and doesnt check bounds anywhere

I've tested the code on arch with bash `5.1.8(1)-release-(x86_64-pc-linux-gnu)` and thats about it

It currently implements:
* A
* NS
* CNAME
* SOA
* MX
* TXT
* AAAA

## Usage
`./resolve.sh google.com A`

## Why?!
Why not?
