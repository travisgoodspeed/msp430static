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



use strict;
use warnings;

use DBI;
use FindBin qw($RealBin);
use lib qw($RealBin);
use GD;  #only needed for memmap.gd.  Comment out if you like.

#use lib qw(/myPerl/myModules/);


require "$RealBin/MSP430static.pm";

MSP430static::main();
