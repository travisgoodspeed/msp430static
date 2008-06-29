#m4s script
#call as "m4s /contribute/lib"


#Verify that we've got enough to contribute.
my $count=dbscalar('select count(*) from lib;');

if($count==0){
    print "Library is empty!\nYou've nothing to contribute. :-(\n";
    return 1;
}

#Then dump the code.
system(
    "echo \"select md5_hex(checksum),name from lib where  md5_hex(checksum)!='d41d8cd98f00b204e9800998ecf8427e';\" |
m4s sql >lib.txt && gzip lib.txt");

#Then beg the user to submit it.
print "Please email ./lib.txt.gz to <tmgoodspeed at gmail.com>\n";
print "with 'CONTRIBUTE_LIB' as the title.\n";
print "Include a description of what's in your library.\n";
print "(No poetry, please, unless it's in msp430 machine language.)\n";


