use 5.008001;
use strict;
use warnings;
use Test::More 0.96;
use Test::Deep '!blessed';

use HTTP::Cookies::Tiny;

my $jar = new_ok("HTTP::Cookies::Tiny");

my @cases = (
    {
        cookie => "",
        parse  => undef,
    },
    {
        cookie => "SID=",
        parse  => undef,
    },
    {
        cookie => "=31d4d96e407aad42",
        parse  => undef,
    },
    {
        cookie => "; Max-Age: 1360343635",
        parse  => undef,
    },
    {
        cookie => "SID=31d4d96e407aad42",
        parse  => {
            name  => "SID",
            value => "31d4d96e407aad42",
        }
    },
    {
        cookie => "SID=31d4d96e407aad42 ; ; ; ",
        parse  => {
            name  => "SID",
            value => "31d4d96e407aad42",
        }
    },
    {
        cookie => "SID=31d4d96e407aad42; Path=/; Secure; HttpOnly",
        parse  => {
            name  => "SID",
            value => "31d4d96e407aad42",
            attr  => {
                path     => "/",
                secure   => 1,
                httponly => 1,
            },
        }
    },
    {
        cookie => "SID=31d4d96e407aad42; Path=/; Domain=example.com",
        parse  => {
            name  => "SID",
            value => "31d4d96e407aad42",
            attr  => {
                path   => "/",
                domain => "example.com",
            },
        }
    },
    {
        cookie => "lang=en-US; Expires = Wed, 09 Jun 2021 10:18:14 GMT",
        parse  => {
            name  => "lang",
            value => "en-US",
            attr  => {
                expires => "Wed, 09 Jun 2021 10:18:14 GMT",
            },
        }
    },
);

for my $c (@cases) {
    my $got = $jar->_parse( $c->{cookie} );
    cmp_deeply $got, $c->{parse}, "Set-Cookie: $c->{cookie}";
}

done_testing;
# COPYRIGHT
