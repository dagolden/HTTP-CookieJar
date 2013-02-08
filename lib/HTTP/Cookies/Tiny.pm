use v5.10;
use strict;
use warnings;

package HTTP::Cookies::Tiny;
# ABSTRACT: A tiny HTTP cookie jar
# VERSION

sub new {
    my ($class) = @_;
    bless {}, $class;
}

sub _parse {
    my ($self, $cookie) = @_;
    my ($kvp, @attrs) = split /;/, $cookie // '';
    my ($name, $value) = map { s/^\s*//; s/\s*$//; $_ } split /=/, $kvp // '';
    return unless length $name && length $value;
    my $parse = {
        name => $name,
        value => $value,
    };
    for my $s ( @attrs ) {
        next unless defined $s && $s =~ /\S/;
        my ($k, $v) = map { s/^\s*//; s/\s*$//; $_ } split /=/, $s;
        $parse->{attr}{lc $k} = $v // 1;
    };
    return $parse;
}

# Date conversions adapted from HTTP::Date
my $DoW = "Sun|Mon|Tue|Wed|Thu|Fri|Sat";
my $MoY = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec";
sub _http_date {
    my ($sec, $min, $hour, $mday, $mon, $year, $wday) = gmtime($_[1]);
    return sprintf("%s, %02d %s %04d %02d:%02d:%02d GMT",
        substr($DoW,$wday*4,3),
        $mday, substr($MoY,$mon*4,3), $year+1900,
        $hour, $min, $sec
    );
}

sub _parse_http_date {
    my ($self, $str) = @_;
    require Time::Local;
    my @tl_parts;
    if ($str =~ /^[SMTWF][a-z]+, +(\d{1,2}) ($MoY) +(\d\d\d\d) +(\d\d):(\d\d):(\d\d) +GMT$/) {
        @tl_parts = ($6, $5, $4, $1, (index($MoY,$2)/4), $3);
    }
    elsif ($str =~ /^[SMTWF][a-z]+, +(\d\d)-($MoY)-(\d{2,4}) +(\d\d):(\d\d):(\d\d) +GMT$/ ) {
        @tl_parts = ($6, $5, $4, $1, (index($MoY,$2)/4), $3);
    }
    elsif ($str =~ /^[SMTWF][a-z]+ +($MoY) +(\d{1,2}) +(\d\d):(\d\d):(\d\d) +(?:[^0-9]+ +)?(\d\d\d\d)$/ ) {
        @tl_parts = ($5, $4, $3, $2, (index($MoY,$1)/4), $6);
    }
    return eval {
        my $t = @tl_parts ? Time::Local::timegm(@tl_parts) : -1;
        $t < 0 ? undef : $t;
    };
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
