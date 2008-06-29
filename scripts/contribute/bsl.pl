#m4s script
#call as "m4s /contribute/bsl"

#First, identify the chip ID.
my $id=bsl_chipid();

if(!$id){
    print "No BSL found.
Be sure to include the region [0c00,1000) when dumping from a hardware chip.\n";
    return 1;
}

print "BSL found for chipid=$id.\n";

#Then dump the code.
system(
    "echo \"select asm from code where address>=dehex('0c00') and address<=dehex('1000');\" |
m4s sql >bsl_$id.txt && gzip bsl_$id.txt");

#Then beg the user to submit it.
print "Please email ./bsl_$id.txt.gz to <tmgoodspeed at gmail.com>\n";
print "with 'CONTRIBUTE_BSL $id' as the title.\n";

