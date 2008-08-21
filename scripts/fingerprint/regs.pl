#m4s script
#call as "m4s /fingerprint/regs"

my $total;

#Dump totals for each register"
foreach("r12","r13","r14","r15"){
    my $reg=$_;
    my $count=dbscalar("select count(*) from code where asm like '%$reg%';");
    print "$reg $count\n";
}

