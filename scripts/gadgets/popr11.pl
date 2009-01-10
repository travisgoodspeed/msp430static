#m4s script
#call as "m4s /gadgets/popr11"

dbexec('select enhex(pop.address) from code pop, code ret where pop.asm like \'%pop%r11%\' and ret.address=pop.address+2 and ret.asm like \'%ret%\';');

dbexec('select count(pop.address),\'Gadgets total.\' from code pop, code ret where pop.asm like \'%pop%r11%\' and ret.address=pop.address+2 and ret.asm like \'%ret%\';');
