#msp430static script
#call as "m4s /loadmacros"


loadmacro(".funcs.top10","sql",
	  "Lists the top ten targets of function calls.",
	  "select count(dest) as a, enhex(dest) from calls group by dest order by a desc limit 10;");

loadmacro(".ivt","sql",
	  "Dumps the Interrupt Vector Table (IVT)",
#	  "select enhex(address),enhex(dest) from ivt;");
	  "select enhex(i.address),enhex(i.dest),(select name from funcs f where f.address=i.dest) from ivt as i;");

loadmacro(".contribute.bsl","sql",
	  "Dumps a file containing the BSL of the current image.",
	  "/contribute/bsl");

loadmacro(".contribute.lib","sql",
	  "Dumps a file containing one-way hashes of the current library.",
	  "/contribute/lib");

loadmacro(".code.drop.ffff","sql",
	  "Drops all lines of 'FFFF FFFF', which are uncleared flash.",
	  "delete from code where asm like '%ff ff ff ff%';");


#This doesn't work.
#     loadmacro(".svn.update","shell",
# 	      "Updates to the latest version by svn.",
# 	      "cd $RealBin && svn update");

loadmacro(".calls.regen","perl",
	  "Regnerate the calls table using dbnetanalyze().",
	  "dbnetanalyze();");

loadmacro(".selftest","perl",
	  "Test the installation and print any errors or warnings.",
	  "selftest();");

loadmacro(".funcs.regen","perl",
	  "Regenerate the functions list from code, calls, and symbols.",
	  "regenfuncs();");
loadmacro(".funcs.overlap","sql",
	  "List overlapping function addresses.",
	  "select enhex(a.address),enhex(b.address)
from funcs a, funcs b where a.address!=b.address
and a.address<b.end and b.address<a.end;");

loadmacro(".symbols.recover","sql",
	  "Recover symbol names from libraries.",
	  "update funcs 
set name=(select name from hashetlib l where l.checksum=md5_hex(funcs.checksum))
where md5_hex(funcs.checksum) in (select checksum from hashetlib);");
loadmacro(".symbols.import.ic7","perl",
	  "Load symbol names from an ImageCraft V7 .mp file.",
	  "readiccv7mp();");
loadmacro(".symbols.import.ic7","perl",
	  "Load symbol names from an ImageCraft V7 .mp file.",
	  "readiccv7mp();");


loadmacro(".callgraph","sql",
	  "Dump a digraph call tree for graphviz.",
	  "select callgraph();");
loadmacro(".callgraph.gv","system",
	  "View a callgraph in ghostview.",
	  "msp430static .callgraph.ps| gv -");
loadmacro(".callgraph.kgv","system",
	  "View a callgraph in kghostview.",
	  "msp430static .callgraph.ps| kghostview -");
loadmacro(".callgraph.xview","system",
	  "View a callgraph in xview.",
	  "msp430static .callgraph | $graphviz -Tgif >.temp.gif && xview .temp.gif; rm -f .temp.gif");
loadmacro(".callgraph.ps","system",
	  "Postscript callgraph, sized for US Letter.",
	  "msp430static .callgraph | $graphviz -Tps -x -Gsize=\"7,10\" -Grankdir=\"LR\"");
loadmacro(".callgraph.lp","system",
	  "Print callgraph for US Letter.",
	  "msp430static .callgraph.ps | lp");
loadmacro(".export.ihex","sql",
	  "Dumps the project as an Intel Hex file.",
	  "select to_ihex(asm) from code union all select ':00000001FF';");

loadmacro(".export.srec","system",
	  "Dumps the project as a Motorolla SRec file.",
	  "msp430static .export.ihex | srec_cat - -Intel");
loadmacro(".export.aout","system",
	  "Dumps the project an a.out executable.",
	  "msp430static .export.ihex >.temp.ihex; msp430-objcopy -I ihex -O elf32-msp430 .temp.ihex a.out; rm -f .temp.ihex");

#FIXME Make this use motelist.
loadmacro(".install.telosb","system",
	  "Installs the project to a TelosB over /dev/ttyUSB0 using tos-bsl.",
	  "m4s .export.ihex | tos-bsl --telosb -c /dev/ttyUSB0 -r -e -I -p -");

loadmacro(".macros","sql",
	  "Lists all available macros.",
	  "select name,comment from macros order by name asc;");
loadmacro(".macros.html","sql",
	  "Lists all available macros in HTML, for the website.",
	  "select
'<dt>'||name||'</dt>',
'<dd>'||comment||'</dd>'
 from macros order by name asc;");
loadmacro(".subs","sql",
	  "Lists all additional SQL functions.",
	  "select name,comment from subs order by name asc;");

loadmacro(".code.missing","sql",
	  "List addresses where code is expected, but does not exist.",
	  "select enhex(address+2) from code
               where address+2 not in (select address from code)
               and address+4 not in (select address from code)
               and address>dehex('0200') and address<dehex('ffe0')
               order by address desc;");

loadmacro(".funcs","sql",
	  "List functions which appear in libraries.",
	  "select distinct enhex(address), name from funcs");

loadmacro(".funcs.inlibs","sql",
	  "List functions which appear in libraries.",
	  "select distinct enhex(f.address), l.name from hashetlib l,
               funcs f where md5_hex(f.checksum)=l.checksum;");

loadmacro(".funcs.notinlibs","sql",
	  "List functiosn which do not appear in libraries.",
	  "select distinct enhex(f.address),f.name from funcs f where
               md5_hex(f.checksum) not in (select checksum from hashetlib);");
loadmacro(".funcs.outside","sql",
	  "List instructions where are not part of any function.",
	  "select asm from code where addr2func(address)=-1
               and address<dehex('ffe0');");

loadmacro(".code.switches","sql",
	  "List branches belonging to jump-table switch statements.",
	  "select asm from code where asm like '%br%(%)%';");

loadmacro(".lib.import.gnu","system",
	  "Import mspgcc libraries from /usr/local/msp430.",
	  "msp430-objdump -D `find /usr/local/msp430 -name \\*.a` | m4s lib");
loadmacro(".lib.import.tinyos","system",
	  "Import TinyOS libraries from /opt/tinyos-2.x.",
	  "msp430-objdump -D `find /opt/tinyos-2.x/apps -name \\*.exe` | m4s lib");
loadmacro(".lib.import.tinyos1","system",
	  "Import old TinyOS libraries from /opt/tinyos-1.x.",
	  "msp430-objdump -D `find /opt/tinyos-1.x/apps -name \\*.exe` | m4s lib");
loadmacro(".lib.import.contiki","system",
	  "Import Contiki 2.x libraries from /opt/contiki-2.x.",
	  "msp430-objdump -D `find /opt/contiki-2.x -name \\*.sky` | m4s lib");
loadmacro(".lib.import.ic7","system",
	  "Import ImageCraft V7 libraries from /opt/iccv7430.",
	  "cat `find /opt/iccv7430/lib -name \*.a` | m4s .input.lib.ic7");

loadmacro(".input.lib.gnu","perl",
	  "Import GCC library from objdump.",
	  "readlib()");
loadmacro(".input.lib.ic7","perl",
	  "Import an ImageCraft 7 library from stdin.",
	  "readiccv7a()");
loadmacro(".input.lib.hashed","perl",
	  "Import hash library.",
	  "inputhashlib()");

loadmacro(".lib.import.hashed","system",
	  "Import standard libraries from $RealBin/libs.",
	  "cat $RealBin/libs/*.txt | m4s .input.lib.hashed");


loadmacro(".memmap.gd.gif","perl",
	  "Output a GIF drawing of memory.",
	  "gdmemmap('gif');");
loadmacro(".memmap.gd.jpeg","perl",
	  "Output a JPEG drawing of memory.",
	  "gdmemmap('jpeg');");
loadmacro(".memmap.gd.png","perl",
	  "Output a PNG drawing of memory.",
	  "gdmemmap('png');");

loadmacro(".memmap.pstricks","perl",
	  "Output a LaTeX drawing of memory.",
	  "pstmemmap('png');");
loadmacro(".memmap.gd.xview","system",
	  "View a callgraph in xview.",
	  "m4s .memmap.gd.gif >.temp.gif && xview .temp.gif; rm -f .temp.gif");
loadmacro(".memmap.gd.eog","system",
	  "View a callgraph in Eye of Gnome.",
	  "m4s .memmap.gd.png >/tmp/foo.png && eog /tmp/foo.png");

loadmacro(".summary","perl",
	  "Output a summary of the database contents.",
	  "printsummary();");

loadmacro(".missing","perl",
	  "Default macro, run whenever a missing macro is called.",
	  "print 'That macro does not exist.\n';");
