use 5.008001;
use strict;
use warnings;

use vars '$public_suffix_module';
$public_suffix_module = 'Mozilla::PublicSuffix';
do './t/publicsuffix.inc';
