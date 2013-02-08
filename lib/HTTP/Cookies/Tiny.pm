use v5.10;
use strict;
use warnings;

package HTTP::Cookies::Tiny;
# ABSTRACT: A tiny HTTP cookie jar
# VERSION

sub new {
    my ($class) = @_;
    bless { store => {} }, $class;
}

sub add {
    my ( $self, $request, $cookie ) = @_;
    my ( $scheme, $host, $port, $request_path ) = _split_url($request);
    my $parse = _parse_cookie($cookie)
      or return;
    # check domain
    my $domain = $parse->{attr}{domain} // $host;
    return unless _domain_match( $host, $domain );
    # check path
    my $path = $parse->{attr}{path} // $request_path;
    # XXX check path
    $self->{store}{$domain}{$path}{ $parse->{name} } = $parse;
}

#--------------------------------------------------------------------------#
# Helper subroutines
#--------------------------------------------------------------------------#

sub _parse_cookie {
    my ($cookie) = @_;
    my ( $kvp, @attrs ) = split /;/, $cookie // '';
    my ( $name, $value ) = map { s/^\s*//; s/\s*$//; $_ } split /=/, $kvp // '';
    return unless length $name && length $value;
    my $parse = { name => $name, value => $value, attr => {} };
    for my $s (@attrs) {
        next unless defined $s && $s =~ /\S/;
        my ( $k, $v ) = map { s/^\s*//; s/\s*$//; $_ } split /=/, $s;
        $k = lc $k;
        next unless $k =~ m/^(?:domain|path|expires|max-age|httponly|secure)$/;
        $v = 1 if $k =~ m/^(?:httponly|secure)$/; # boolean flag if present
        $v = _parse_http_date($v) if $k eq 'expires'; # convert to epoch
        next unless length $v;
        $v =~ s{^\.}{} if $k eq 'domain';             # strip leading dot
        $parse->{attr}{ lc $k } = $v;
    }
    return $parse;
}

sub _domain_match {
    my ( $string, $dom_string ) = @_;
    return 1 if $dom_string eq $string;
    return unless $string =~ /[a-z]/i;                # non-numeric
    if ( $string =~ s{\Q$dom_string\E$}{} ) {
        return substr( $string, -1, 1 ) eq '.';       # "foo."
    }
    return;
}

# Date conversions adapted from HTTP::Date
my $DoW = "Sun|Mon|Tue|Wed|Thu|Fri|Sat";
my $MoY = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec";

sub _http_date {
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday ) = gmtime(shift);
    return sprintf(
        "%s, %02d %s %04d %02d:%02d:%02d GMT",
        substr( $DoW, $wday * 4, 3 ),
        $mday,
        substr( $MoY, $mon * 4, 3 ),
        $year + 1900,
        $hour, $min, $sec
    );
}

sub _parse_http_date {
    my ($str) = @_;
    require Time::Local;
    my @tl_parts;
    if (
        $str =~ /^[SMTWF][a-z]+, +(\d{1,2}) ($MoY) +(\d\d\d\d) +(\d\d):(\d\d):(\d\d) +GMT$/ )
    {
        @tl_parts = ( $6, $5, $4, $1, ( index( $MoY, $2 ) / 4 ), $3 );
    }
    elsif (
        $str =~ /^[SMTWF][a-z]+, +(\d\d)-($MoY)-(\d{2,4}) +(\d\d):(\d\d):(\d\d) +GMT$/ )
    {
        @tl_parts = ( $6, $5, $4, $1, ( index( $MoY, $2 ) / 4 ), $3 );
    }
    elsif ( $str
        =~ /^[SMTWF][a-z]+ +($MoY) +(\d{1,2}) +(\d\d):(\d\d):(\d\d) +(?:[^0-9]+ +)?(\d\d\d\d)$/
      )
    {
        @tl_parts = ( $5, $4, $3, $2, ( index( $MoY, $1 ) / 4 ), $6 );
    }
    return eval {
        my $t = @tl_parts ? Time::Local::timegm(@tl_parts) : -1;
        $t < 0 ? undef : $t;
    };
}

sub _split_url {
    my $url = pop;

    # URI regex adapted from the URI module
    # XXX path_query here really chops at ? or # to get just the path and not the query
    my ( $scheme, $authority, $path_query ) = $url =~ m<\A([^:/?#]+)://([^/?#]*)([^#?]*)>
      or die(qq/Cannot parse URL: '$url'\n/);

    $scheme = lc $scheme;
    $path_query = "/$path_query" unless $path_query =~ m<\A/>;

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

  use HTTP::Cookies::Tiny;

=head1 DESCRIPTION

This module might be cool, but you'd never know it from the lack
of documentation.

=head1 USAGE

Good luck!

=head1 SEE ALSO

Maybe other modules do related things.

=cut

# vim: ts=4 sts=4 sw=4 et:
