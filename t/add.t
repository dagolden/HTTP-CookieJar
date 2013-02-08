use 5.008001;
use strict;
use warnings;
use Test::More 0.96;
use Test::Deep '!blessed';

use HTTP::Cookies::Tiny;

my $jar = new_ok("HTTP::Cookies::Tiny");

my @cases = (
    {
        label   => "no cookies",
        request => "http://example.com/",
        cookies => [],
        store   => {},
    },
    {
        label   => "invalid cookie not stored",
        request => "http://example.com/",
        cookies => ["SID="],
        store   => {},
    },
    {
        label   => "different domain not stored",
        request => "http://example.com/",
        cookies => ["SID=31d4d96e407aad42; Domain=example.org"],
        store   => {},
    },
    {
        label   => "subdomain not stored",
        request => "http://example.com/",
        cookies => ["SID=31d4d96e407aad42; Domain=www.example.com"],
        store   => {},
    },
    {
        label   => "superdomain",
        request => "http://www.example.com/",
        cookies => ["SID=31d4d96e407aad42; Domain=example.com"],
        store   => {
            'example.com' => {
                '/' => {
                    SID => {
                        name  => "SID",
                        value => "31d4d96e407aad42",
                        attr  => {
                            domain => "example.com",
                        },
                    }
                }
            },
        },
    },
    {
        label   => "simple key=value",
        request => "http://example.com/",
        cookies => ["SID=31d4d96e407aad42"],
        store   => {
            'example.com' => {
                '/' => {
                    SID => {
                        name  => "SID",
                        value => "31d4d96e407aad42",
                        attr  => {},
                    }
                }
            },
        },
    },
##    {
##        cookies => ["SID=31d4d96e407aad42; Path=/; Secure; HttpOnly"],
##        store   => {},
##    },
##    {
##        cookies => ["SID=31d4d96e407aad42; Path=/; Domain=example.com"],
##        store   => {},
##    },
##    {
##        cookies => ["SID=31d4d96e407aad42; Path=/; Domain="],
##        store   => {},
##    },
##    {
##        cookies => ["lang=en-US; Expires = Wed], 09 Jun 2021 10:18:14 GMT"],
##        store   => {},
##    },
##    {
##        cookies => ["lang=en-US; Expires = Wed], 09 Jun 2021 10:18:14 GMT; Max-Age=3600"],
##        store   => {},
##    },
);

for my $c (@cases) {
    for my $cookie ( @{ $c->{cookies} } ) {
        $jar->add( $c->{request}, $cookie );
    }
    cmp_deeply $jar->{store}, $c->{store}, $c->{label};
}

done_testing;
# COPYRIGHT
