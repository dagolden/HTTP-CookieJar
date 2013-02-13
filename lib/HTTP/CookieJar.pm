use v5.10;
use strict;
use warnings;

package HTTP::CookieJar;
# ABSTRACT: A minimalist HTTP user agent cookie jar
# VERSION

use Carp ();
use HTTP::Date ();

sub new {
    my ($class) = @_;
    bless { store => {} }, $class;
}

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

sub clear {
    my ($self) = @_;
    $self->{store} = {};
    return 1;
}

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
    return sort {
        length( $b->{path} ) <=> length( $a->{path} )
          || $a->{creation_time} <=> $b->{creation_time}
    } @found;
}

sub cookie_header {
    my ( $self, $req ) = @_;
    return join( "; ", map { "$_->{name}=$_->{value}" } $self->cookies_for($req) );
}

# generate as list that can be fed back in to add
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

# returns self
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
    my ( $name,   $value )   = map { s/^\s*//; s/\s*$//; $_ } split /=/, $kvp // '', 2;
    return unless length $name;
    my $parse = { name => $name, value => $value // "" };
    for my $s (@attrs) {
        next unless defined $s && $s =~ /\S/;
        my ( $k, $v ) = map { s/^\s*//; s/\s*$//; $_ } split /=/, $s, 2;
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

This module might be cool, but you'd never know it from the lack
of documentation.

=head1 USAGE

Good luck!

=head1 SEE ALSO

Maybe other modules do related things.

=cut

# vim: ts=4 sts=4 sw=4 et:
