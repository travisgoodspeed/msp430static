#!/bin/zsh
echo "Erasing old database, if one exists."
rm -f 430static.db
echo "Disassembling and importing tnbelt.exe."
msp430-objdump -d -m msp430 tnbelt.exe | m4s init
echo "Done."
