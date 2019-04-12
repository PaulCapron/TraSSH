#!/bin/sh
# sudo apt install openssh-client -- normally installed by default

echo This process should hang!
sleep .5

exec ssh -vv localhost
