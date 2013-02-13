use v5.10;
use strict;
use warnings;

package HTTP::CookieJar;
# ABSTRACT: A minimalist HTTP user agent cookie jar
# VERSION

use Carp ();
use HTTP::Date ();

=construct new

    my $jar = HTTP::CookieJar->new;

Return a new, empty cookie jar

=cut

sub new {
    my ($class) = @_;
    bless { store => {} }, $class;
}

=method add

    $jar->add(
        "http://www.example.com/", "lang=en-US; Path=/; Domain=example.com"
    );

Given a request URL and a C<Set-Cookie> header string, attempts to adds the
cookie to the jar.  If the cookie is expired, instead it deletes any matching
cookie from the jar.  A C<Max-Age> attribute will be converted to an absolute
C<Expires> attribute.

It will throw an exception if the request URL is missing or invalid.  Returns true if
successful cookie processing or undef/empty-list on failure.

=cut

sub add {
    my ( $self, $request, $cookie ) = @_;
    my ( $scheme, $host, $port, $request_path ) = eval {_split_url($request)};
    Carp::croak($@) if $@;

    return unless my $parse = _parse_cookie($cookie);
    my $name = $parse->{name};
    # check and normalize domain
    # XXX doesn't check for public suffixes; see Mozilla::PublicSuffix
    if ( exists $parse->{domain} ) {
        return unless _domain_match( $host, $parse->{domain} );
    }
    else {
        $parse->{domain}   = $host;
        $parse->{hostonly} = 1;
    }
    my $domain = $parse->{domain};
    # normalize path
    if ( !exists $parse->{path} || substr( $parse->{path}, 0, 1 ) ne "/" ) {
        $parse->{path} = _default_path($request_path);
    }
    my $path = $parse->{path};
    # set timestamps and normalize expires
    my $now = $parse->{creation_time} = $parse->{last_access_time} = time;
    if ( exists $parse->{'max-age'} ) {
        $parse->{expires} = $now + delete $parse->{'max-age'};
    }
    # update creation time from old cookie, if exists
    if ( my $old = $self->{store}{$domain}{$path}{$name} ) {
        $parse->{creation_time} = $old->{creation_time};
    }
    # if cookie has expired, purge any old matching cookie, too
    if ( defined $parse->{expires} && $parse->{expires} < $now ) {
        delete $self->{store}{$domain}{$path}{$name};
    }
    else {
        $self->{store}{$domain}{$path}{$name} = $parse;
    }
    return 1;
}

=method clear

    $jar->clear

Empties the cookie jar.

=cut

sub clear {
    my ($self) = @_;
    $self->{store} = {};
    return 1;
}

=method cookies_for

    my @cookies = $jar->cookies_for("http://www.example.com/foo/bar");

Given a request URL, returns a list of hash references representing cookies
that should be sent.  The hash references are copies -- changing values
will not change the cookies in the jar.

Cookies set 'secure' will only be returned if the request scheme is 'https'.
Expired cookies will not be returned.

Keys of a cookie hash reference might include:

=for :list
* name -- the name of the cookie
* value -- the value of the cookie
* domain -- the domain name to which the cookie applies
* path -- the path to which the cookie applies
* expires -- if present, when the cookie expires in epoch seconds
* secure -- if present, the cookie was set 'Secure'
* httponly -- if present, the cookie was set 'HttpOnly'
* hostonly -- if present, the cookie may only be used with the domain as a host
* creation_time -- epoch seconds since the cookie was first stored
* last_access_time -- epoch seconds since the cookie was last stored

Keep in mind that 'httponly' means it should only be used in requests and not
made available via Javascript, etc.  This is pretty meaningless for Perl user
agents.

Generally, user agents should use the C<cookie_header> method instead.

It will throw an exception if the request URL is missing or invalid.

=cut

sub cookies_for {
    my ( $self, $request ) = @_;
    my ( $scheme, $host, $port, $request_path ) = eval { _split_url($request) };
    Carp::croak($@) if $@;

    my @found;
    my $now = time;
    for my $cookie ( $self->_all_cookies ) {
        next if $cookie->{hostonly}           && $host ne $cookie->{domain};
        next if $cookie->{secure}             && $scheme ne 'https';
        next if defined( $cookie->{expires} ) && $cookie->{expires} < $now;
        next unless _domain_match( $host, $cookie->{domain} );
        next unless _path_match( $request_path, $cookie->{path} );
        push @found, $cookie;
    }
    @found = sort {
        length( $b->{path} ) <=> length( $a->{path} )
          || $a->{creation_time} <=> $b->{creation_time}
    } @found;
    return @found;
}

=method cookie_header

    my $header = $jar->cookie_header("http://www.example.com/foo/bar");

Given a request URL, returns a correctly-formatted string with all relevant
cookies for the request.  This string is ready to be used in a C<Cookie> header
in an HTTP request.  E.g.:

    SID=31d4d96e407aad42; lang=en-US

It follows the same exclusion rules as C<cookies_for>.

If the request is invalid or no cookies apply, it will return an empty string.

=cut

sub cookie_header {
    my ( $self, $req ) = @_;
    return join( "; ", map { "$_->{name}=$_->{value}" } $self->cookies_for($req) );
}

=method dump_cookies

    my @list = $jar->dump_cookies;
    my @list = $jar->dump_cookies( { persistent => 1 } );

Returns a list of raw cookies in string form.  The strings resemble what
would be received from C<Set-Cookie> headers, but with additional internal
fields.  The list is only intended for use with C<load_cookies> to allow
cookie jar persistence.

If a hash reference with a true C<persistent> key is given as an argument,
cookies without an C<Expires> time (i.e. "session cookies") will be omitted.

Here is a trivial example of saving a cookie jar file with L<Path::Tiny>:

    path("jar.txt")->spew( join "\n", $jar->dump_cookies );

=cut

sub dump_cookies {
    my ( $self, $args ) = @_;
    my @list;
    for my $c ( $self->_all_cookies ) {
        my @parts = "$c->{name}=$c->{value}";
        if ( defined $c->{expires} ) {
            push @parts, 'Expires=' . HTTP::Date::time2str( $c->{expires} );
        }
        else {
            next if $args->{persistent};
        }
        for my $attr (qw/Domain Path Creation_Time Last_Access_Time/) {
            push @parts, "$attr=$c->{lc $attr}" if defined $c->{ lc $attr };
        }
        for my $attr (qw/Secure HttpOnly HostOnly/) {
            push @parts, $attr if $c->{ lc $attr };
        }
        push @list, join( "; ", @parts );
    }
    return @list;
}

=method load_cookies

    $jar->load_cookies( @cookies );

Given a list of cookie strings from C<dump_cookies>, it adds them to
the cookie jar.  Cookies added in this way will supercede any existing
cookies with similar domain, path and name.

It returns the jar object for convenience when loading a new object:

    my $jar = HTTP::CookieJar->new->load_cookies( @cookies );

Here is a trivial example of loading a cookie jar file with L<Path::Tiny>:

    my $jar = HTTP::CookieJar->new->load_cookies(
        path("jar.txt")->lines
    );

=cut

sub load_cookies {
    my ( $self, @cookies ) = @_;
    for my $cookie (@cookies) {
        my $p = _parse_cookie( $cookie, 1 );
        next unless exists $p->{domain} && exists $p->{path};
        $p->{$_} //= time for qw/creation_time last_access_time/;
        $self->{store}{ $p->{domain} }{ $p->{path} }{ $p->{name} } = $p;
    }
    return $self;
}

#--------------------------------------------------------------------------#
# private methods
#--------------------------------------------------------------------------#

# return a copy of all cookies
sub _all_cookies {
    return map {
        { %$_ }
    } map { values %$_ } map { values %$_ } values %{ $_[0]->{store} };
}

#--------------------------------------------------------------------------#
# Helper subroutines
#--------------------------------------------------------------------------#

my $pub_re = qr/(?:domain|path|expires|max-age|httponly|secure)/;
my $pvt_re = qr/(?:$pub_re|creation_time|last_access_time|hostonly)/;

sub _parse_cookie {
    my ( $cookie, $private ) = @_;
    my ( $kvp,    @attrs )   = split /;/, $cookie // '';
    my ( $name,   $value )   = map { s/^\s*//; s/\s*$//; $_ } split /=/, $kvp // '', 2; ## no critic
    return unless length $name;
    my $parse = { name => $name, value => $value // "" };
    for my $s (@attrs) {
        next unless defined $s && $s =~ /\S/;
        my ( $k, $v ) = map { s/^\s*//; s/\s*$//; $_ } split /=/, $s, 2; ## no critic
        $k = lc $k;
        next unless $private ? ( $k =~ m/^$pvt_re$/ ) : ( $k =~ m/^$pub_re$/ );
        $v = 1 if $k =~ m/^(?:httponly|secure|hostonly)$/; # boolean flag if present
        $v = HTTP::Date::str2time($v) // 0 if $k eq 'expires'; # convert to epoch
        next unless length $v;
        $v =~ s{^\.}{}                            if $k eq 'domain'; # strip leading dot
        $v =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg if $k eq 'path';   # unescape
        $parse->{$k} = $v;
    }
    return $parse;
}

sub _domain_match {
    my ( $string, $dom_string ) = @_;
    return 1 if $dom_string eq $string;
    return unless $string =~ /[a-z]/i;                               # non-numeric
    if ( $string =~ s{\Q$dom_string\E$}{} ) {
        return substr( $string, -1, 1 ) eq '.';                      # "foo."
    }
    return;
}

sub _default_path {
    my ($path) = @_;
    return "/" if !length $path || substr( $path, 0, 1 ) ne "/";
    my ($default) = $path =~ m{^(.*)/};                              # greedy to last /
    return length($default) ? $default : "/";
}

sub _path_match {
    my ( $req_path, $cookie_path ) = @_;
    return 1 if $req_path eq $cookie_path;
    if ( $req_path =~ m{^\Q$cookie_path\E(.*)} ) {
        my $rest = $1;
        return 1 if substr( $cookie_path, -1, 1 ) eq '/';
        return 1 if substr( $rest,        0,  1 ) eq '/';
    }
    return;
}

sub _split_url {
    my $url = shift;
    die(qq/No URL provided\n/) unless length $url;

    # URI regex adapted from the URI module
    # XXX path_query here really chops at ? or # to get just the path and not the query
    my ( $scheme, $authority, $path_query ) = $url =~ m<\A([^:/?#]+)://([^/?#]*)([^#?]*)>
      or die(qq/Cannot parse URL: '$url'\n/);

    $scheme = lc $scheme;
    $path_query = "/$path_query" unless $path_query =~ m<\A/>;
    $path_query =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;

    my $host = ( length($authority) ) ? lc $authority : 'localhost';
    $host =~ s/\A[^@]*@//; # userinfo
    my $port = do {
        $host =~ s/:([0-9]*)\z// && length $1
          ? $1
          : ( $scheme eq 'http' ? 80 : $scheme eq 'https' ? 443 : undef );
    };

    return ( $scheme, $host, $port, $path_query );
}

1;

=for Pod::Coverage method_names_here

=head1 SYNOPSIS

  use HTTP::CookieJar;

  my $jar = HTTP::CookieJar->new;

  # add cookie received from a request
  $jar->add( "http://www.example.com/", "CUSTOMER=WILE_E_COYOTE" );

  # extract cookie header for a given request
  my $cookie = $jar->cookie_header( "http://www.example.com/" );

=head1 DESCRIPTION

This module implements a minimalist HTTP user agent cookie jar in
conformance with L<RFC 6265|http://tools.ietf.org/html/rfc6265>.

Unlike the commonly used L<HTTP::Cookies> module, this module does
not require use of L<HTTP::Request> and L<HTTP::Response> objects.
An LWP-compatible adapter is availabe as L<HTTP::CookieJar::LWP>.

=head1 LIMITATIONS AND CAVEATS

=head2 RFC 6265 vs prior standards

This modules adheres as closely as possible to the user-agent rules
of RFC 6265.  Therefore, it does not handle nor generate C<Set-Cookie2>
and C<Cookie2> headers, implement C<.local> suffixes, or do path/domain
matching in accord with prior RFC's.

=head2 Internationalzed domain names

Internationalized domain names given in requests must be properly
encoded in ASCII form.

=head2 Public suffixes

Cookies that set the C<Domain> value to a public suffix are currently
permitted.  This is likely to change in a future release.

=head2 Third-party cookies

According to RFC 6265, a cookie may be accepted only if has no C<Domain>
attribute (in which case it is "host-only") or if the C<Domain> attribute is a
suffix of the request URL.  This effectively prohibits Site A from setting a
cookie for unrelated Site B, which is one potential third-party cookie vector.

=head1 SEE ALSO

Maybe other modules do related things.

=cut

# vim: ts=4 sts=4 sw=4 et:
