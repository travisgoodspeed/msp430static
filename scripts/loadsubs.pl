#msp430static script
#call as "m4s /loadsubs"


loadsub('enhex', 1, 'perl',
	'Converts a numeral to a hex string.',
	'sub { return sprintf("%04x",shift()); }');
loadsub('perl', 1, 'perl',
	'Evaluates a statement in perl.',
	'sub { return eval(shift); }');
loadsub('md5_hex', 1, 'perl',
	'Returns the md5 checksum of the input.',
	'sub { return md5_hex(shift); }');

loadsub('insflow',1,'perl',
	'Dumps the flow information of an instruction for graphviz.',
	'sub { return insflow(shift);}');
loadsub('inscount',1,'perl',
	'Counts the number of instructions in a string.',
	'sub { return inscount(shift);}');
loadsub('insshort',1,'perl',
	'Shortens an instruction.',
	'sub { return insshort(shift);}');
loadsub('fnflow',1,'perl',
	'Dumps the flow information of a function for graphviz.',
	'sub { return fnflow(shift);}');

loadsub('inslen',1,'perl',
	'Returns the number of bytes of an instruction.  (2 or 4)',
	'sub {return inslen(shift);}');
loadsub('insop',1,'perl',
	'Returns the opcode of an instruction.',
	'sub {return insop(shift);}');
loadsub('insjmpoff',1,'perl',
	'Returns the relative offset of a jmp instruction',
	'sub {return insjmpoff(shift);}');
loadsub('insjmpabs',1,'perl',
	'Returns the absolute target of a jmp instruction',
	'sub {return insjmpabs(shift);}');


loadsub('bsl_chipid',0,'perl',
	'Returns the hex chip id from the BSL ROM at 0xff0.',
	'sub {return bsl_chipid();}');

loadsub('dehex', 1, 'perl',
	'Converts a hex string to a numeral.',
	'sub { return hex(shift()); }');


loadsub('fprint', 1, 'perl',
	'Position-invariant fingerprint of an assembly code string.',
	'sub { return fprintfunc(shift()); }');
loadsub('addr2func', 1, 'perl',
	'Returns the starting address of the function containing the given address.',
	'sub { return addr2func(shift()); }');
loadsub('addr2funcname', 1, 'perl',
	'Returns the name of the function containing the given address.',
	'sub { return addr2funcname(shift()); }');
loadsub('callgraph', 0, 'perl',
	'Returns a graphviz callgraph.',
	'sub { return callgraph(); }');
loadsub('to_ihex', 1, 'perl',
	'Returns a line of code as an Intel Hex entry.  [broken]',
	'sub { return to_ihex(shift()); }');

#VERY slow, don't use this.
loadsub('topcode',0,'perl',
	"Returns the address of the greatest address of code.",
	"sub { print '.\n'; return 
             dbscalar(\"
                select address from code where address<dehex('ffe0')
                order by address desc limit 1;
             \") ; }");
