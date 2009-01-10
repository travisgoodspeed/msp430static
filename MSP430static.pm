#!/usr/bin/perl

# msp430static.pl
# A static analysis tool for the MSP430 by Travis Goodspeed.
# Copyright (C) 2008 Travis Goodspeed

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


#To install prereq, either
#  perl -MCPAN -e shell
#  install GD
#or
#  sudo g-cpan -i GD

package MSP430static;

use strict;
use warnings;

use DBI;
use FindBin qw($RealBin);
use GD;  #only needed for memmap.gd.  Comment out if you like.

my %opts;

#database handle
my $dbh;


#Use fdp for massive graphs.
our $graphviz='fdp';

require Digest::MD5;
import Digest::MD5 'md5_hex';

sub main{
    initopts();
    dbopen();
    loadmacros();
    loadsubs();
    
    if($opts{"lib"}){
	#readlib();
	dbexec(".input.lib.gnu");
    }elsif($opts{"init"} || $opts{"reload"}){
	resetdb() if $opts{"init"};
	resetdbreload() if $opts{"reload"};
	dbindex();
	readin();
	dbinit();
	dbanalyze();
    }
    
    #Slowly deprecating in favor of macros.
    print "digraph g{\n" if  $opts{"graph"};
    
    rlshell() if $opts{"dbshell"} || $opts{"shell"};
    dbshell() if $opts{"sql"};
    
    #Macros accepted at end of command-line.
    my %foo=%opts;
    foreach(%foo){
	dbexec($_) if /\A\..*/ || /\A\/.*/;
    }
    
    dbclose();
    print "}\n" if  $opts{"graph"};
}

#Loads subs from the database.
sub loadoldsubs{
    my $adr=shift();
    my $sth = $dbh->prepare('SELECT name,args,lang,comment,code FROM subs;')
	or die "Couldn't prepare statement: " . $dbh->errstr;
    
    $sth->execute()             # Execute the query
	or die "Couldn't execute statement: " . $sth->errstr;

    # Read the matching records and print them out          
    while (my @data = $sth->fetchrow_array()) {
	my $name=$data[0];
	my $args=$data[1];
	my $lang=$data[2];
	my $comment=$data[3];
	my $code=$data[4];
	
	regsub($name,$args,$lang,$code);
    }
    $sth->finish;
}

#Loads a function into the database.
sub loadsub{
    my $name=shift();
    my $args=shift();
    my $lang=shift();
    my $comment=shift();
    my $code=shift();
    
    my $sth;
    
    #Drop the old entry
    $sth = $dbh->prepare("delete from subs where name=?;");
    $sth->execute($name);
    $sth->finish();
    
    #Add the new entry.
    $sth = $dbh->prepare("INSERT INTO subs VALUES (?, ?, ?, ?, ?);");
    $sth->execute($name, $args, $lang, $comment, $code);
    $sth->finish();
    
    regsub($name,$args,$lang,$code);
}

#registers a function in $dbh
#name, args, lang, code
sub regsub{
    my $name=shift();
    my $args=shift();
    my $lang=shift();
    my $code=shift();
    print "reging\t$name\t\t$code\n" if $opts{"debug"};
    $dbh->func($name,$args, eval($code), 'create_function' );
}

#Loads all default functions into the database.
sub loadsubs{
    $dbh->do("CREATE TABLE  if not exists subs(
name varchar,args varchar,
lang varchar,comment varchar,code varchar);");
    loadoldsubs();
    scriptexec("/loadsubs");
}


#Load a macro and insert it into the database, replacing any prior copy.
sub loadmacro{
    my $name=shift();
    my $lang=shift();
    my $comment=shift();
    my $code=shift();
    #$macros{"$name"}=$code;
    my $sth;
    
    #Drop the old entry
    $sth = $dbh->prepare("delete from macros where name=?;");
    $sth->execute($name);
    $sth->finish();
    
    #Add the new entry.
    $sth = $dbh->prepare("INSERT INTO macros VALUES (?, ?, ?, ?);");
    $sth->execute($name, $lang, $comment, $code);
    $sth->finish();
}

#Print an error if a unix command doesn't exist in PATH.
sub reqcmd{
    my $cmd=shift();
    my $app=shift();
    system("which $cmd >/dev/null 2>/dev/null || echo ERROR:   $app not found.");
}

#Print a warning if a unix command doens't exist in PATH.
sub reccmd{
    my $cmd=shift();
    my $app=shift();
    system("which $cmd >/dev/null 2>/dev/null || echo WARNING: $app not found.");
}

#Tests to see that all necessary libraries are intact.
sub selftest(){
    use GD::Image;
    #use Boost::Graph;
    print "Looking for required commands:\n";
    reqcmd($graphviz,
	   "Graphviz");
    reccmd('xview',
	   'XView');
    reccmd('kghostview',
	   'KGhostView');
    reqcmd('msp430-objdump',
	   'MSPGCC msp430objdump');
    reqcmd('msp430-gcc',
	   'MSPGCC');
    reccmd('eog',
	   'Eye of GNOME');
}

#Note that errors are suppressed within a macro.
#(I don't know why.)
sub loadmacros{
    $dbh->do("
CREATE TABLE IF NOT EXISTS
              macros(
              name varchar,
              lang varchar,
              comment varchar,
              code varchar);
");

    scriptexec("/loadmacros");
}


#TODO: Replace this with Getopt::Long
sub initopts{
    my $count=0;
        
    for(@ARGV){
	$count++;
	$opts{$_}=1;
	if($_ eq "--help" or $_ eq "-h"){
	    print "Usage: $0 [options]
\t[options] are:
noindex     Do not create indices.  (faster write, slower reads)

init        Initialize the database with a source file.
  <app.s    Application to read.
reload      Same as above, but doesn't kill history and pins.
  <app.s
lib         Accept a library with debugging symbols as input, writing
            a checksummed account of functions to the database.
  <libc.s   Assembly file to read.
index       Create indices on the database.
shell       Interactive SQL shell.
sql         Non-interactive SQL shell, for scripting.
graph       Surrounds output with 'digraph g{...}'.  Useful for graphviz.
";
	    exit;
	}
    }
    $opts{"shell"}=1 if $count<1;
    
}



#my( @calls, @callfrom);



#connect to the database
sub dbopen{
    my $databasefile="";
    $databasefile="430static.db";# if $opts{"dbwrite"};
    my $dburl=$ENV{'M4SDB'};
    $dburl= "dbi:SQLite:$databasefile" if !$dburl;
    print "Connecting to $dburl\n" if $opts{"debug"};
    $dbh = DBI->connect($dburl) || die "Cannot connect to $dburl";
    print "Database connected.\n" if $opts{"debug"};
    
}

#Returns the starting address of the function containing the given address.
sub addr2func{
    my $adr=shift();
    my $sth = $dbh->prepare('SELECT distinct address FROM funcs where address<=? order by address desc limit 1;')
	or die "Couldn't prepare statement: " . $dbh->errstr;
    
    $sth->execute($adr)
	or die "Couldn't execute statement: " . $sth->errstr;

    # Read the matching records and print them out          
    while (my @data = $sth->fetchrow_array()) {
	my $address = $data[0];
	return $address;
    }
    
    if ($sth->rows == 0) {
	return -1;
    }
    
    $sth->finish;
}

# sub oldaddr2func{
#     my $adr=shift();
#     my $sth = $dbh->prepare('SELECT distinct address FROM funcs where address<=? and end>=?;')
# 	or die "Couldn't prepare statement: " . $dbh->errstr;
    
#     $sth->execute($adr,$adr)             # Execute the query
# 	or die "Couldn't execute statement: " . $sth->errstr;

#     # Read the matching records and print them out          
#     while (my @data = $sth->fetchrow_array()) {
# 	my $address = $data[0];
# 	return $address;
#     }
    
#     if ($sth->rows == 0) {
# 	return -1;
#     }
    
#     $sth->finish;
# }



#Returns the name field of the function containing the given address.
sub addr2funcname{
    my $adr=shift();
    my $sth = $dbh->prepare('SELECT distinct name FROM funcs where address<=? and end>=?;')
	or die "Couldn't prepare statement: " . $dbh->errstr;
    
    $sth->execute($adr,$adr)             # Execute the query
	or die "Couldn't execute statement: " . $sth->errstr;

    # Read the matching records and print them out          
    while (my @data = $sth->fetchrow_array()) {
	my $address = $data[0];
	return $address;
    }
    
    if ($sth->rows == 0) {
	return -1;
    }
    
    $sth->finish;
}


sub dbindex{
    $dbh->do("CREATE INDEX IF NOT EXISTS adcode ON code(address);");
    $dbh->do("CREATE INDEX IF NOT EXISTS nlib ON lib(name);");
    $dbh->do("CREATE INDEX IF NOT EXISTS clib ON lib(checksum);");
    $dbh->do("CREATE INDEX IF NOT EXISTS nfuncs ON funcs(name);");
    $dbh->do("CREATE INDEX IF NOT EXISTS cfuncs ON funcs(checksum);");
}

#write to the database
#see resetdb() for table creations.
sub dbinit{
    #require DBI;
    #DBI->import;
    
    my ($i, $res, $tmp);
    
    regenfuncs();
    
    $dbh->do("CREATE INDEX IF NOT EXISTS adfuncs ON funcs(address,end);")
	if !$opts{"noindex"};
    
}

sub regenfuncs{
    my $c=dbrows("select distinct enhex(dest) from calls union select distinct enhex(dest) from ivt;");
    #@called sucks, use
    #select distinct enhex(dest) from calls;
    
    my $i;
    $dbh->do("delete from funcs;");
    for(@$c){
	my $R=$_->[0];
	my $name=$R;
	$i=hex($R);
	my $sname=dbscalar("SELECT name from symbols where address=$i");
	$name=$sname if $sname;
	
	printf "#Identified function: $name at 0x%X\n",$i  if $opts{"debug"};
	
	my $r= getroutine(hex($R));
	my $fingerprint=fprintfunc($r);
	my $fnend=fnend($r);
	#print "$fnend\n";
	$dbh->do("INSERT INTO funcs VALUES ($i,$fnend,'$r','$name','$fingerprint');");
	#print $r if $opts{"code"};
    }
}

#summarize the contents of the database
sub printsummary{
    my $code=dbscalar("SELECT count(*) FROM code;");
    my $funcs=dbscalar("SELECT count(*) FROM funcs;");
    my $lib=dbscalar("SELECT count(*) FROM lib;");
    my $libfuncs=dbscalar("SELECT count(distinct l.checksum) FROM lib l, funcs f
                           WHERE l.checksum=f.checksum;");
    my $pokes=dbscalar("SELECT count(distinct address) FROM pokes;");
    my $fbegin=dbscalar("SELECT enhex(min(address)) from code;");
    my $fend=dbscalar("SELECT enhex(max(address)) from code where address<dehex('0xFF00');");
    printf "$RealBin/msp430static.pl\n";
    printf "$code instructions
$funcs functions from $fbegin to $fend
$libfuncs of $lib library functions found
$pokes distinct memory locations are poked.
\n";
    
    my $res = $dbh->selectall_arrayref( q( SELECT  count(*) FROM lib;));
    foreach( @$res ) {
	print "$_->[0] lib functions.\n";
    }
    
    $res = $dbh->selectall_arrayref( q( SELECT  count(distinct name) FROM lib;));
    foreach( @$res ) {
	print "$_->[0] unique lib function names.\n";
    }
    
    $res = $dbh->selectall_arrayref( q( SELECT  count(distinct checksum) FROM lib;));
    foreach( @$res ) {
	print "$_->[0] unique lib function checksums.\n";
    }
}


#Get a human-readable name of a function
#by the integer of its starting address.
sub getfnname{
    my $fn=int(shift);
    my $name=dbscalar("select l.name from lib l,funcs f
where l.checksum=f.checksum and f.address=$fn");
    return $name if $name;
    return sprintf("%04x",$fn);
}

my @codecache;
#Gets a line of code from the database.
sub dbcode{
    my $adr=shift;#better be integer
    my $code=$codecache[$adr];
    return $code if($code && ($codecache[$adr] ne "MISSING"));
    $code=$codecache[$adr]=dbscalar("select asm from code where address=$adr");
    $codecache[$adr]="MISSING" if(!$code);
    $code="" if $codecache[$adr] eq "MISSING";
    return $code;
}

#Gets a scalar from the database.
sub dbscalar{
    my $query=shift;
    printf "$query\n" if $opts{'debug'};
    #First, name our vertices.
    my $res=$dbh->selectall_arrayref($query);
    #if(!$res){return '';}
    foreach(@$res){
	return $_->[0];
    }
    return "";
}
#Get rows from the database
sub dbrows{
    my $query=shift;
    printf "$query\n" if $opts{'debug'};
    #First, name our vertices.
    my $res=$dbh->selectall_arrayref($query);
    return $res;
    #foreach(@$res){
    #return $_->[0];
    #}
    #return "";
}



#Database shell.  Useful for additional instructions.
sub dbshell{
    my $query=shift;
    #First, name our vertices.
    my $res;
    printf("Starting shell.\n") if $opts{"debug"};
    
    #printf "m4s>";
    while(<STDIN>){
 	$res=$dbh->selectall_arrayref(dbpreproc($_));
 	foreach(@$res){
 	    my $i=-1;
 	    while($_->[++$i]){
 		printf "%s\t",$_->[$i];
 	    }
 	    printf "\n";
 	}
 	#printf "m4s>";
    }
    printf("Stopping shell.\n") if $opts{"debug"};
}


#Database shell.  Useful for additional instructions.
sub rlshell{
    require Term::ReadLine;
    Term::ReadLine->import;
    
    print "msp430static r";
    system "svn info $RealBin  | grep Revision | sed 's/Revision: //';";
    print "from ";
    system "svn info $RealBin | grep Date | sed 's/.*(//' | sed 's/)//'";
    print "
Copyright (c) 2008, Travis Goodspeed <travis at utk.edu>

This program is free software. You can distribute it and/or modify it
under the terms of the GNU General Public License version 2.\n";
    
    my $term = new Term::ReadLine 'msp430static';
    my $prompt = "m4s> ";
    my $OUT = $term->OUT || \*STDOUT;
        
    #Load history from database.
    my $res=$dbh->selectall_arrayref("select cmd from history where id>(select max(id)-100 from history) order by id asc;");
    foreach(@$res){
	$term->addhistory($_->[0]) if /\S/;
    }
    
    my $cmd='select 1';
    while ( defined ($cmd=$term->readline($prompt)) ) {
	#Update the history.
	
	#Thanks to Jonathan Sailor for this bit,
	#which allows a line to continue if ended in a \.
	while ($cmd =~ /\\\s*$/) {
	    #print "foo\n";
	    $cmd=~ s/\\\s*$//;
	    printf "$cmd...\n";
	    my $more = $term->readline($prompt);
	    if (defined $more) {
		$cmd .= $more;
	    } else {
		last;
	    }
	}
	
	#Add to history
	my $sth = $dbh->prepare("INSERT INTO history VALUES (NULL, ?);");
	$sth->execute($cmd);
	$sth->finish();
	
	#Then exec.
	dbexec(dbpreproc($cmd));
    }
    
}

#Execute a script.
sub scriptexec{
    my $cmd=shift;
    my $file="$RealBin/scripts$cmd.pl";
    do $file;
}

#Execute a macro, in any language, from the macros table.
sub macroexec{
    my $cmd=shift;
    my $sth = $dbh->prepare("SELECT name,lang,comment,code FROM
macros WHERE name=?");
    $sth->execute($cmd);
    my $d = $sth->fetchrow_arrayref;
    
#     #This should make it easy to move macros into scripts.
#     if($!d){
# 	my $script=$cmd;
# 	$cmd~=s/\./\//g;
	
# 	if (-e "$RealBin/scripts$script.pl"){
# 	    scriptexec($file);
# 	    return;
# 	}
#     }

    return macroexec(".missing") if(!$d) ;
    
    #Do the actual execution.
    dbexec($d->[3]) if $d->[1] eq 'sql';
    eval($d->[3])   if $d->[1] eq 'perl';
    system($d->[3]) if $d->[1] eq 'system';
    
    #Clean up.
    $sth->finish();
}

#Shorten an instruction
sub insshort{
    $_=shift;
    my $ret='';
    for(split /\n/){
	
	s/^ *//;
	s/\t/ /g;
	s/(\s[a-f1-90]{2}\s)/ /g;
	s/(\s[a-f1-90]{2}\s)/ /g;
	s/(\s[a-f1-90]{2}\s)/ /g;
	s/ +/ /g;
	s/;.*//g;
	
	
	$ret.="$_";
    }
    return $ret;
}

#Count the instructions within a string.
sub inscount{
    $_=shift;
    my $i=0;
    for(split /\n/){
	$i++;
    }
    return $i;
}

#TODO finish this
sub instime{
    my $ins=shift;
    
}

#Generate an instruction flow graph.
sub insflow{
    my $ins=shift;
    my $shortins=insshort($ins);
    my $len=inslen($ins);
    $len=2 if $len==0;
    $ins=~/(\w+):/;
    my $adr=hex($1);
    my $hadr=$1;
    my $next=$adr+$len;
    my $op=insop($ins);
    my $jmptarg=insjmpabs($ins);
    
    #return "+$len at $adr";
    my $ret="";
    $ret.="$adr -> $next;\n" 
	if insop($ins) ne 'ret' &&
	insop($ins) ne 'jmp';
    $ret.="$adr -> $jmptarg [color=green label=\"2c\"];\n" if $jmptarg>0;
    $ret.="$adr [label=\"$shortins\"];";
}

#Generate an instruction flow graph for many instructions.
sub fnflow{
    my $graph="";
    $_=shift;
    for(split /\n/){
	$graph.=insflow($_);
    }
    return "digraph g{\n$graph\n}";
}

#generate an flow graph for a region
sub regflow{
    my $start=shift;
    my $end=shift;
    print "digraph g{\n";
    
    print "}";
}

#length of an instruction in bytes
sub inslen{
    $_=shift;
    if ($_ =~ /\s(.*):\s(.. ..) (.. ..)\s\t([^ \t]{2,5})/){
	return 4 if($3 ne '     ');
	return 2;
    }
    return 0;
}
#length of an instruction in bytes
sub insop{
    $_=shift;
    if ($_ =~ /\s(.*):\s(.. ..) (.. ..)\s\t([^ \t]{2,5})/){
	return $4;
    }
    return '????';
}
#offset of a jump instruction
sub insjmpoff{
    $_=shift;
    if ($_ =~ /\$([^ ]*)/){
	return $1;
    }
    return 0;
}
#offset of a jump instruction
sub insjmpabs{
    $_=shift;
    if ($_ =~ /abs 0x(\w*)/){
	return hex($1);
    }
    return 0;
}


#Preprocess an SQL string.
sub dbpreproc{
    my $cmd=shift;
    
    #Replace hex with decimal.
    #FIXME make this only match a word of 0x, outside of quotes.
    while($cmd=~/\b0x([0-9a-fA-F]+)\b/){
	my $hex=$1;
	my $dec=hex($hex);
	$cmd=~s/0x$hex/$dec/g;
    }
    
    print "postproc: $cmd\n\n" if $opts{'debug'};
    return $cmd;
}

#Executes an instruction or macro.
sub dbexec{
    my $cmd=shift;
    #if($macros{$cmd}){
    #dbexec($macros{$cmd});
    #return;
    #}
    
    if($cmd=~/\A\/.*/){
	scriptexec($cmd);
	return;
    }

    if($cmd=~/\A\..*/){
	macroexec($cmd);
	return;
    }
 
#This test doesn't work.
#TODO rewrite and enable.
#    if($cmd=~/^select/ || $cmd=~/^SELECT/){
	my $res=$dbh->selectall_arrayref($cmd) || return;
	foreach(@$res){
	    my $i=-1;
	    while($_->[++$i]){
		printf "%s",$_->[$i];
		printf "\t" if($_->[$i+1]);#print tab if not last
	    }
	    printf "\n";
	}
#    }else{
#	$dbh->do($cmd);
#   }
    
	
}

#Fingerprint a series of assembly instructions.
sub fprintfunc{
    my $fprint="";
    $_=shift;
    for(split(/\n/)){
	#print "FOO $_\n" if $opts{"debug"};
	#if ($_ =~ /\s(.*):\s(.. .. .. ..)\s\t([^ \t]{2,5})\s([^;]*)\s;*\s?(.*)/){
	if ($_ =~ /\s(.*):\s(.. .. .. ..)/){
	    $fprint.="$2";
	}elsif ($_ =~ /\s(.*):\s(.. ..)/){
	    $fprint.="$2";
	}else{
	    print "ERROR: Unparsable instruction: $_\n" if $opts{"debug"};
	}
    }
    $fprint=~s/ //g;
    printf "FINGERPRINTED AS $fprint\n" if $opts{"debug"};
    return $fprint;
}

#Print a line as an ihex record.
#http://pages.interlog.com/~speff/usefulinfo/Hexfrmt.pdf 
sub to_ihex{
    my $code=shift(); #one line for now.
    my ($ihex,$reclen,$offset,$type,$data,$chksum);
    
    $type=0; #always a data record.
    
    #I'm ashamed of this line, but it fixes the regex below
    #when the entry is very short, as in non-code entries.
    $code.="               ";
    
    if ($code =~ / *\s(.*):\s(.. .. .. ..)/){
	$offset=hex($1); #Offset is the address.
	
	$data=$2;
	$data=~s/ //g;
	
	print "data=$data\n" if $opts{"debug"};
	
	$reclen=length($data)/2;
    }else{
	return "ERROR ON $code";
    }
    #$ihex=":$reclen$offset$type$data$chksum";
    $data =~ tr/a-f/A-F/;
    $reclen=length($data)/2;			  
    $ihex= sprintf("%02X%04X%02X%s",
		   $reclen,
		   $offset,
		   $type,
		   $data);
    #Calculate checksum, which when byte-summed with $ihex ought to equal 0.
    my $sum=0;
    #$ihex="12345";
    for(my $i=0;$i<length($ihex);$i+=2){
	my $byte=substr($ihex,$i,2);
	#print "$i $byte\n" if $opts{"debug"];
	$sum+=hex($byte);
    }
    #Wikipedia:
    #It is calculated by adding together the hex-encoded bytes
    #(hex digit pairs), taking only the LSB, and either subtracting
    #the byte from 0x100 or inverting the byte (XORing 0xFF) and adding one (1).
    $chksum=$sum ^ 0xFF; #bitwise xor
    $chksum++;
    $chksum%=0x100;
    printf("ERROR: Checksum doesn't match.\n")
	if(($sum+$chksum)%0x100!=0);
    printf("Checksum is %02X\n",$chksum) if $opts{"debug"};
    
    return sprintf(":%s%02X",$ihex,$chksum);
}

sub dbclose{
    $dbh->disconnect;
    #print "Database disconnected.\n" if $opts{"debug"};    
}



#Convert an address in memory to coordinates on a memmap.
sub addr2memcart{
    my $addr=shift;
    #X is the lower byte, Y is the higher byte.
    #The result is a 256x256 grid for all of MSP430 memory.
    my $x=$addr%256;
    my $y=int($addr/256);
    return "($x , $y)";
}
sub addrx{
    return shift()%256;
}
sub addry{
    return int(shift()/256);
}

#Insert a symbol into the symbols table and update funciton entries.
sub insym{
    my $adr=shift();
    my $name=shift();
    #insert into symbols(address,name);
    my $sth = $dbh->prepare("insert into symbols values (?,?);");
    $sth->execute($adr,$name);
    $sth->finish();
    
    $sth = $dbh->prepare("update funcs set name=? where address=?;");
    $sth->execute($name,$adr);
    $sth->finish();
}

#Insert an entry into the code table.
sub incode{
    my $adr=shift();
    my $code=shift();
    $code =~ s/\s+$//;#strip surrounding whitespace.
    $dbh->do("INSERT INTO code VALUES ($adr, '$code');");
    $codecache[$adr]=$code;
}

#Add an entry to IVT.
sub inivt{
    #print "Marking IVT Table Entry:\n";
    
    my $adr=hex($1);
    my $target=hex($3);
    $dbh->do("INSERT INTO ivt VALUES ($adr, $target);");
}

#Add a note.
sub innote{
    my $adr=$1;
    my $note=$2;
    my $sth = $dbh->prepare(
	'INSERT INTO notes(address, comment)
         VALUES(?,?);')
	or die "Couldn't prepare statement: " . $dbh->errstr;
    
    $sth->execute($1,$2)             # Execute the query
	or die "Couldn't execute statement: " . $sth->errstr;

}

#Read an invalid instruction into the code table, for use as data.
sub indat{
    incode(hex($1),$_);
}



#Read in an instruction.
sub inins{
    #TODO add a progress meter.
    #This can take a long time on the 430x chips.
    
    #print "Marking function:\n";
    #1: address
    #2: Up to four bytes in little-endian, like "30 41" for 0x4130.
    #3: Instruction, like "jmp" or "mov.b"
    #4: All params, unparsed.
    #5: comments, everything after ';'.
    print "$1|$2|$3|$4|$5\n" if($opts{'verbose'});
    my $at=hex($1);

    incode(hex($1),$_);
    
    #look for pokes
    my $poke=$4;
    if($poke && $poke=~/&0x(....)/){
	$poke=hex($1);
	#printf "Poke to $poke\n";
	$dbh->do("INSERT INTO pokes VALUES ($poke,$at);");
    }
    
}


#Given an address within a routine, this prints the whole routine.
#It works by backing up to the preceding 'ret' or call target,
#then copying until the final 'ret'.
sub getroutine{
    my $addr=(shift)-2;
    my $cmd='';
    my $res='';
    
    #This is the local jump limit.
    #The function cannot end before this address.
    my $rjmplimit=0;
    
    #back up to one more than previous ret or call target.
    #This might give us trouble.
    my $blanks=0;
    
    #prints everything until the first 'ret'.
    while(
	#Local limits.
	(
	 (!($cmd =~/ret/) && !($cmd=~/jmp\s*\$\+0/) && !($cmd=~/br/) && !($blanks>5))
	 ||
	 ($addr<$rjmplimit)
	)
	
	#Global limits.  Something is wrong if these become relevant.
	&& $addr<0xffde && $addr>0 && $addr<0xFFFF
	){
	
	#$cmd=$code[$addr+=2]; #fixme
	$cmd=dbcode($addr+=2);
	if($cmd ne ''){
	    $res.="$cmd\n";
	    $blanks=0;
	}else{
	    $blanks++;
	}
	#Update $rjmplimit if we are at a relative jump.
	if($cmd=~/abs 0x(....)/){
	    #printf "rjmplimit=0x$1\n";
	    $rjmplimit=hex($1)
		if(hex($1)>$rjmplimit);
	}
    }
    return $res;
}


#Determine ending address of a function, given the assembly.
sub fnend{
    my $fn=shift;
    my $lline='';
    my $ladr=0;
    $_=$fn;
    for(split(/\n/)){
	#$lline=$_;
	#printf "Trying $_\n";
	if(/(\w*):/){
	    $ladr=hex($1);
	    #printf "It might end at $ladr\n";
	}
    }
    
    return $ladr;
}


#Identify function calls from database.
sub dbnetanalyze{
    my $rows;
    
    #$dbh->do("delete from calls;");
    $dbh->do("DROP TABLE IF EXISTS calls;");
    $dbh->do("CREATE TABLE calls(src int, dest int, at int);");
    
    
    #Grab calls.
    $rows=dbrows("select asm from code where asm like '%call%';");
    foreach(@$rows){
	my $line=$_->[0];
	if($line=~/(\w*):.*call.*0x(\w*)/){
	    my $at=hex($1);
	    my $to=hex($2);
	    my $src=addr2func($at);
	    $dbh->do("INSERT INTO calls(src,at,dest) VALUES ($src,$at,$to)");
	}else{
	    print "WTF (dbnetanalyze): $line\n" if $opts{"wtf"};
	}
    }
    
    
    #Grab absolute branches.
#     m4s sql> select asm from code where asm like '%br%';                                                                   
#     4036:       30 40 dc 43     br      #0x43dc         ;
#     403a:       30 40 3e 40     br      #0x403e         ;
#     4124:       10 4f 28 41     br      16680(r15)              ;
#     4564:       30 40 58 4a     br      #0x4a58         ;
    
    $rows=dbrows("select asm from code where asm like '%30 40%br%';");
    foreach(@$rows){
	my $line=$_->[0];
	if($line=~/(\w*):.*30 40.*br.*0x(\w*)/){
	    my $at=hex($1);
	    my $to=hex($2);
	    my $src=addr2func($at);
	    $dbh->do("INSERT INTO calls(src,at,dest) VALUES ($src,$at,$to)");
	}else{
	    print "WTF (dbnetanalyze): $line\n" if $opts{"wtf"};
	}
    }
    
    $dbh->do("delete from calls where src=0;"); #Replace this.
    
    #Grab a branch table?
    #http://travisgoodspeed.blogspot.com/2008/02/switchcase-headaches-in-msp430-assembly.html
    
}

#Read a library, marking symbol names and checksums.
#This lets us identify function in executables without symbol names.
sub readlib(){
    my $working=1;
    my $fprint="";
    my $fname="";
    my $nextfn="";
    my $asm="";
#read each line and load it.
    
    while(<STDIN>){
	
	if($_=~/(stab)/ && $working){
	    $working=0;
	    print "#Stopping work until out of stab section.\n" if $opts{"debug"};
	}elsif(!$working){
	    print "#Ignoring\n#$_" if $opts{"debug"} && $opts{"verbose"};
	    if($_=~/(section)/){
		$working=1;
		print "#Resuming work, as out of stab section.\n" if $opts{"debug"};
	    }
	}
	    
	#Instructions
	#    11b6:       6f 4e           mov.b   @r14,   r15     ;
	#    11b8:       cd 4f 00 00     mov.b   r15,    0(r13)  ;
	#    1111:       22222222222     33333   44444444444444  555555
	#    f896:	     30 40 a2 f8 	br	#0xf8a2		;
	elsif ($_ =~ /\s(.*):\s(.. .. .. ..)\s\t([^ \t]{2,5})\s([^;]*)\s;*\s?(.*)/){
	    #inins();
	    printf "GOT $2 from $_\n" if $opts{"debug"};
	    $fprint.=$2;
	    $asm.=$_;
	    #FIXME: There's no need to checksum here.
	    #Perhaps run:
	    #update lib set checksum=fprint(asm);
	    #(Would ruin import from ICC.)
	#}elsif ($_ =~ /00000000 <(.*)>/){
	}elsif ($_ =~ /........ <(.*)>/){
	    $nextfn=$1;
	    
	    $fprint=~s/fi//g;
	    printf "#fingerprinted $fname\n";
	    printf "#as $fprint\n" if $opts{"debug"};
	    #$dbh->do("INSERT INTO lib(name,checksum,asm) VALUES ('$fname','$fprint', '$asm');");
	    inlib($fname,$fprint,$asm);
	    #printf "New function $nextfn\n";
	    $fname="$nextfn";
	    $fprint="";
	    $asm="";
	}elsif ($_ =~/(\w*):  (.. ..)/){
	    $asm.=$_;
	    $fprint.=$2; #perhaps innapropriate?
	#For debugging, should only be non-executable parts and section headers
	}else{
	    print "WTF: $_" if $opts{"wtf"};
	}
	#printf "$2\n";
	print "$_" if $opts{"printall"};
    }
    
    $dbh->do("DELETE FROM lib WHERE checksum='';");
    my $res = $dbh->selectall_arrayref( q( SELECT  count(*) FROM lib;));
    foreach( @$res ) {
	print "#$_->[0] lib functions.\n";
    }
    
    $res = $dbh->selectall_arrayref( q( SELECT  count(distinct name) FROM lib;));
    foreach( @$res ) {
	print "#$_->[0] unique lib function names.\n";
    }
    
    $res = $dbh->selectall_arrayref( q( SELECT  count(distinct name) FROM lib;));
    foreach( @$res ) {
	print "#$_->[0] unique lib function checksums.\n";
    }
}



#Resets part of the database to reload a new binary without clobbering lib.
sub resetdbreload(){

    $dbh->do("DROP TABLE IF EXISTS pokes;");
    $dbh->do("CREATE TABLE pokes(address int,at int);");
    
    $dbh->do("DROP TABLE IF EXISTS ivt;");
    $dbh->do("CREATE TABLE ivt (address int, dest int);");
    
    $dbh->do( "DROP TABLE IF EXISTS code;");
    $dbh->do( "CREATE TABLE code (address int, asm);");
    
    $dbh->do( "DROP TABLE IF EXISTS notes;");
    $dbh->do( "CREATE TABLE notes (address int, comment varchar);");
    
    $dbh->do( "DROP TABLE IF EXISTS symbols;");
    $dbh->do( "CREATE TABLE symbols (address int, name);");
    
    $dbh->do("DROP TABLE IF EXISTS funcs;");
    $dbh->do("CREATE TABLE funcs(address int,end int, asm, name, checksum);");
    
    $dbh->do("DROP TABLE IF EXISTS calls;");
    $dbh->do("CREATE TABLE calls(src int, at int, dest int);");
    
    $dbh->do("DROP VIEW IF EXISTS fcalled;");
    $dbh->do("CREATE VIEW fcalled as
              SELECT dest FROM calls UNION SELECT dest FROM ivt;");
}

#Resets the database by destroying and recreating tables.
sub resetdb(){
    resetdbreload();
    print "Resetting database\n" if $opts{"debug"};
    $dbh->do("DROP TABLE IF EXISTS lib;");
    $dbh->do("CREATE TABLE lib(name,comment,source,checksum,asm);");
    
    $dbh->do("DROP TABLE IF EXISTS hashlib;");
    $dbh->do("CREATE TABLE hashlib(name,checksum);");
    
    #dbexec('.lib.import.hashed');
    
    $dbh->do("DROP TABLE IF EXISTS history;");
    $dbh->do("CREATE TABLE history(id INTEGER PRIMARY KEY, cmd);");
    
    
    $dbh->do("DROP VIEW IF EXISTS hashetlib;");
    $dbh->do("CREATE VIEW hashetlib as
              SELECT name,checksum FROM hashlib UNION SELECT name,md5_hex(checksum) FROM lib;");
}

sub readin{
    my $working=1;
    
    print "Reading code.\n";

    #Delete analysis.
    $dbh->do("DELETE FROM code;");
    $dbh->do("DELETE FROM funcs;");
    $dbh->do("DELETE FROM calls;");
    $dbh->do("DELETE FROM ivt;");
    $dbh->do("DELETE FROM pokes;");
    $dbh->do("DELETE FROM notes;");
    
    #read each line and load it.
    while(<STDIN>){
	
	
	if($_=~/(stab)/ && $working){
	    $working=0;
	    print "#Stopping work until out of stab section.\n" if $opts{"debug"};
	}elsif(!$working){
	    print "#Ignoring\n#$_" if $opts{"debug"} && $opts{"verbose"};
	    if($_=~/(section)/){
		$working=1;
		print "#Resuming work, as out of stab section.\n" if $opts{"debug"};
	    }
	    
	    #IVT Entries
	    #    fffe:       00 11           interrupt service routine at 0x1100
	    #~ /[\s\t]*(\w*):[\s\t]*(.. ..)[\s\t]*interrupt service routine at 0x(....)/;
	}elsif($_ =~ /[\s\t]*(....):[\s\t]*(.. ..)[\s\t]*interrupt service routine at 0x(....)/){
	    inivt() ;
	    inins();
	}
	
	#Instructions
	#    11b6:       6f 4e           mov.b   @r14,   r15     ;
	#    11b8:       cd 4f 00 00     mov.b   r15,    0(r13)  ;
	#    1111:       22222222222     33333   44444444444444  555555
	#    f896:	     30 40 a2 f8 	br	#0xf8a2		;
	elsif ($_ =~ /\s(\w*):\s(.. .. .. ..)\s\t([^ \t]{2,5})\s([^;]*)\s;*\s?(.*)/){
	    inins();
	}
	
	elsif ($_ =~ /(.*) <(.*)>/){
	    #printf "%08x: %s\n",hex($1),$2;
	    insym(hex($1),$2);
	    
	}elsif ($_ =~/\s(\w*):\s(.. ..)\s/){
	    #$asm.=$_;
	    #$fprint.=$2; #perhaps innapropriate?
	    indat();
	}elsif($_=~/#(\w\w\w\w) (.*)/){
	    #print "$1:\t$2\n";
	    innote(hex($1),$2);
	#For debugging, should only be non-executable parts and section headers
	}else{
	    print "WTF: $_" if($opts{"wtf"});
	}
	print "$_" if $opts{"printall"};
    }
}

#Read a hashed library file as made by .contribute.lib
sub inputhashlib(){
    print "Reading library hashes.\n";
    while(<STDIN>){
	if($_=~/(................................)\s*(\w+)/){
	    #print "Got $2 and $1\n";
	        my $sth = $dbh->prepare(
		    'insert into hashlib(name,checksum)
values(?,?);')
		    or die "Couldn't prepare statement: " . $dbh->errstr;
		
		$sth->execute($2,$1)
		    or die "Couldn't execute statement: " . $sth->errstr;
	}else{
	    print "WTF $_\n" if $opts{'wtf'};
	}
    }
}

#Read a .mp file from ICCv7.
sub readiccv7mp(){
    my $working=1;
    
    #Delete analysis.
    $dbh->do("DELETE FROM symbols;");
    
    #read each line and load it.
    while(<STDIN>){
	if ($_ =~/\s*([0-9A-F]{4})\s*(\w+)\s*\n/){
	    printf ("found $2 at $1\n") if($opts{"debug"});
	    insym(hex($1),$2);
	    
	}else{
	    print "WTF: $_" if($opts{"wtf"});
	}
	print "$_" if $opts{"printall"};
    }
}
#Read a .a file from ICCv7.
sub readiccv7a(){
    my $working=1;
    
    #Delete analysis.
    #$dbh->do("DELETE FROM symbols;");
    
    
    my ($fn, $print, $asm);
    
    #read each line and load it.
    while(<STDIN>){
	
	#if ($_ =~/\s*([0-9A-F]{4})\s*(\w+)\s*\n/){
	#    printf ("found $2 at $1\n")
	#    insym(hex($1),$2);
	
	if($_=~/\.start/){
	    printf("Found .start.\n")  if($opts{"debug"} && $opts{"verbose"});
	    $fn='';
	    $print='';
	    $asm='';
	}elsif($_=~/\.end/){
	    printf("Found .end, inserting record.\n")  if($opts{"debug"} && $opts{"verbose"});
	    printf "#fingerprinted $fn\n";
	    printf "#as $print\n" if $opts{"debug"};
	    inlib($fn,$print,$asm);
	}elsif($_=~/S (\w+) Def0000/){
	    printf "Found S line for $1\n"  if($opts{"debug"} && $opts{"verbose"});
	    $fn=$1;
	}elsif($_=~/T (.. ..) (.*)\n/){
	    #In reading a T-line, we assume the code is in order.
	    #This isn't required by the standard, but is true of AS430 and ICCV7
	    $print.=$2;
	}else{
	    print "WTF: $_" if($opts{"wtf"});
	}
	
	print "$_" if $opts{"printall"};
    }
}

#insert a new entry into the library table.
sub inlib{
    my $fname=shift;
    my $fprint=shift;
    my $asm=shift;
    
    #Clean up the fingerprint.
    $fprint=~s/ //g;
    $fprint=~s/\r//g;    #Remove CR, which sometimes sneaks in.
    $fprint=lc($fprint);
    
    $dbh->do("INSERT INTO lib(name,checksum,asm)
              VALUES ('$fname','$fprint', '$asm');");
}


sub dbanalyze{
    dbnetanalyze();  #Get calls.
    regenfuncs();    #Get functions.
    dbnetanalyze();  #Fix call names.
}



#Print a memory map for LaTeX/PSTricks.
#This works, but will crash LaTeX for larger projects.
sub pstmemmap{
    printf "\\psset{dotscale=3.0 0.2}\n";
    
    printf "\\psset{linecolor=red}\n";
    printf "%% Begin code.\n";
    #Draw code in red.
    my $res=$dbh->selectall_arrayref(q(SELECT address FROM code));
    foreach(@$res){
	my $cart=addr2memcart($_->[0]);
	printf("\\psdot$cart \t%% %04x\n",$_->[0]);
    }
    
    printf "\\psset{linecolor=blue}\n";
    printf "%% Begin globals.\n";
    #Draw global addresses in blue.
    $res=$dbh->selectall_arrayref(q(SELECT distinct address FROM pokes));
    foreach(@$res){
	my $cart=addr2memcart($_->[0]);
	printf("\\psdot$cart \t%% %04x\n",$_->[0]);
    }
    
    printf "\\psset{linecolor=cyan}\n";
    printf "%% Begin IVT.\n";
    #Draw IVT in green.
    $res=$dbh->selectall_arrayref(q(SELECT distinct address FROM ivt));
    foreach(@$res){
	my $cart=addr2memcart($_->[0]);
	printf("\\psdot$cart \t%% %04x\n",$_->[0]);
    }
}





sub printcallgraph{
    print callgraph();
}
sub callgraph{
    
    my $graph;
    $graph= "digraph g {\n";
    #$graph.="graph [rankdir = \"LR\"];\n";
    #$graph.="graph [width=6  height=10 fixedsize=true];\n";
    #$graph.="graph [pagewidth=6 pageheight=10];\n";

    my $res=$dbh->selectall_arrayref(
	q(select address,name,enhex(address)
          from funcs as f;));
    foreach(@$res){
	my($address,$name,$haddr);
	$address=$_->[0];
	$name=$_->[1];
	$haddr=$_->[2];
	$graph.="$address [label=\"$haddr\\n$name\" shape=\"record\"]\n";
    }
    
    #Next, draw some edges!
    $res=$dbh->selectall_arrayref(
	q(select src,dest,enhex(at) from calls;));
    foreach(@$res){
	my($src,$dest,$at);
	$src=$_->[0];
	$dest=$_->[1];
	$at=$_->[2];
	$graph.="$src -> $dest [label=\"$at\"];\n";
    }

    
    #Next, draw some IVT edges!
    $res=$dbh->selectall_arrayref(
	q(select 'IVT',dest from ivt;));
    foreach(@$res){
	my($src,$dest);
	$src=$_->[0];
	$dest=$_->[1];
	$graph.="$src -> $dest;\n";
    }
    
    $graph.= "}\n";
    return $graph;
    
}

#Print a memory map using GD.
sub gdmemmap{
    require GD;
    GD->import;
    
    my $type=shift();
    
    #Create an image
    my $im = new GD::Image(256,256);
    
    # Allocate some colors
    my $white = $im->colorAllocate(255,255,255);
    my $black = $im->colorAllocate(0,0,0);
    my $grey = $im->colorAllocate(100,100,100);
    my $red = $im->colorAllocate(255,0,0);
    my $blue = $im->colorAllocate(0,0,255);
    my $green = $im->colorAllocate(0,255,0);
    my $iocolor = $im->colorAllocate(0,0,100);
    
    # Make the background transparent and interlaced
    #$im->transparent($white);
    #$im->interlaced('true');
    
    # Draw memory divisions.
    #$im->rectangle(0,256-0,256,256-200,$black);
    # And fill it with red
    #$im->fill(1,256-1,$red);
    
    #Draw code in red.
    my $res=$dbh->selectall_arrayref(q(SELECT address,asm FROM code));
    foreach(@$res){
	my($address,$asm,$x,$y,$color);
	$address=$_->[0];
	$asm=$_->[1];
	$x=addrx($address);
	$y=addry($address);
	
	$color=$red;
	$color=$grey if $asm=~/.*word.*/;
	$color=$black if $asm=~/.*ff ff ff ff.*/;
	
	
	$y=256-$y; #flip vertically.
	$im->setPixel($x,$y,$color);
	$im->setPixel($x+1,$y,$color);
	
	if($asm=~/.*\w\w \w\w \w\w \w\w.*/){
	    $x=addrx($address+2);
	    $y=addry($address+2);
	    
	    $y=256-$y; #flip vertically.
	    $im->setPixel($x,$y,$color);
	    $im->setPixel($x+1,$y,$color);
	}
    }
    
    #Draw global addresses in blue.
    $res=$dbh->selectall_arrayref(q(SELECT distinct address FROM pokes));
    foreach(@$res){
	my($address,$x,$y,$color);
	$color=$blue;
	$address=$_->[0];
	$x=addrx($address);
	$y=addry($address);
	$y=256-$y; #flip vertically.
	$color=$iocolor if $address<0x200;
	
	$im->setPixel($x,$y,$color);
	$im->setPixel($x+1,$y,$color);
	#$im->setPixel($x+2,$y,$blue);
	#$im->setPixel($x+3,$y,$blue);
    }
    
    #Draw IVT in green.
    $res=$dbh->selectall_arrayref(q(SELECT distinct address FROM ivt));
    foreach(@$res){
	my($address,$x,$y);
	$address=$_->[0];
	$x=addrx($address);
	$y=addry($address);
	$y=256-$y; #flip vertically.
	$im->setPixel($x,$y,$green);
	$im->setPixel($x+1,$y,$green);
	$im->setPixel($x+2,$y,$green);
	$im->setPixel($x+3,$y,$green);
    }

    # Open a file for writing 
    #open(PICTURE, ">picture.gif") or die("Cannot open file for writing");

    # Make sure we are writing to a binary stream
    binmode STDOUT; #PICTURE;

    # Convert the image to PNG and print it to the file PICTURE
    print STDOUT $im->gif if $type eq "gif";
    print STDOUT $im->jpeg if $type eq "jpeg";
    print STDOUT $im->png if $type eq "png";
    close STDOUT;
}

sub bsl_chipid(){
    my $line=dbscalar("select asm from code where address like dehex('ff0');");
    if($line=~ m/.*ff0:\s*(.. ..).*/){
	my $id=$1;
	$id=~s/ //;
	return $id;
    }else{
	return 0;
    }
}

sub md5sum{
    return md5_hex(shift);
}


#main();
1;
