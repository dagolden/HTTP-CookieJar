use 5.008001;
use strict;
use warnings;
use Test::More 0.96;
use Test::Deep '!blessed';

use HTTP::Cookies::Tiny;

my @cases = (
    {
        label   => "path length",
        request => "http://example.com/foo/bar/",
        sleep => 0,
        cookies => [
            "SID=2; Path=/",
            "SID=1; Path=/foo",
            "SID=0; Path=/foo/bar",
        ],
    },
    {
        label   => "creation date",
        request => "http://example.com/foo/bar/",
        sleep => 2,
        cookies => [
            "SID=1; Path=/",
            "SID=0; Path=/",
        ],
    },
);

for my $c (@cases) {
    my $jar = HTTP::Cookies::Tiny->new;
    for my $cookie ( @{ $c->{cookies} } ) {
        $jar->add( $c->{request}, $cookie );
        sleep $c->{sleep} if $c->{sleep};
    }
    my @cookies = $jar->cookies_for( $c->{request} );
    my @vals = map { $_->{value} } @cookies;
    cmp_deeply \@vals, [0 .. $#vals], $c->{label} or diag explain \@cookies;
}

done_testing;
# COPYRIGHT
