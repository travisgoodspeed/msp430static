#m4s script
#call as "m4s /fingerprint/regs"


dbexec('select distinct enhex(addr2func(address)),addr2funcname(address),asm from code where asm like \'%&%x00%;%\' or asm like \'%&%x01%;%\';');


