#m4s script
#call as "m4s /gadgets/popr11popr10"



dbexec('select enhex(pop.address) from code pop, code popb, code ret
where pop.asm like \'%pop%r11%\'
and popb.asm like \'%pop%r10%\'
and ret.address=pop.address+4
and popb.address=pop.address+2
and ret.asm like \'%ret%\';');

dbexec('select count(pop.address),\'gadgets total.\' from code pop, code popb, code ret
where pop.asm like \'%pop%r11%\'
and popb.asm like \'%pop%r10%\'
and ret.address=pop.address+4
and popb.address=pop.address+2
and ret.asm like \'%ret%\';');

