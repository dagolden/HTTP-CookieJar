use 5.008001;
use strict;
use warnings;
use Test::More 0.96;
use Test::Deep '!blessed';
use Path::Tiny;

use HTTP::CookieJar;

my $jar = HTTP::CookieJar->new;
my $jar2;

my @cookies = (
    'SID=31d4d96e407aad42; Path=/; Secure; HttpOnly',
);

my $file = Path::Tiny->tempfile;

subtest "empty cookie jar" => sub {
    my $jar = HTTP::CookieJar->new;
    ok( $jar->save("$file"), "save cookie jar");
    ok( my $jar2 = HTTP::CookieJar->new->load("$file"), "load cookie jar" );
    is( scalar $jar2->_all_cookies, 0, "jar is empty" );
};

subtest "roundtrip" => sub {
    my $jar = HTTP::CookieJar->new;
    $jar->add("http://www.example.com/", $_) for @cookies;
    ok( $jar->save("$file"), "save cookie jar");
    ok( my $jar2 = HTTP::CookieJar->new->load("$file"), "load cookie jar" );
    is( scalar $jar2->_all_cookies, 1, "jar has a cookie" );
    cmp_deeply( $jar, $jar2, "old and new jars are the same" );
};

# test cookie jar load without private stuff


done_testing;
# COPYRIGHT
# vim: ts=4 sts=4 sw=4 et:
