#!/bin/zsh
echo "Erasing old database, if one exists."
rm -f 430static.db
echo "Disassembling and importing tnbelt.exe."
msp430-objdump -D -m msp430 tnbelt.hex | m4s init
echo "Done."
