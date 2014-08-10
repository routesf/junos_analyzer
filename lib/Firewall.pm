#!/usr/bin/perl5.12 -w
##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 08/06/2013
##
##-----------------------------------------------------------------------

package Firewall;
use strict;
use Exporter;
use vars qw(@ISA @EXPORT);
use AnalysisCommon;

@ISA = qw(Exporter);
@EXPORT = qw(
	analyze_firewall
);

## output format for firewall summary, use array to ensure the output order
my $firewall_summary = [
		{'summary' => "IPv4 filter", 'number' => 0, 'name' => []},
		{'summary' => "IPv6 filter", 'number' => 0, 'name' => []},
];
## summary end

## show summary result for routing related parts
sub show_summary {
		my %args = (
				'summary' => undef,
				'verbose' => 0,
				'layer' => 1,
				@_,
		);
		my $summary_ref = $args{'summary'};
		my $verbose = $args{'verbose'};
		my $layer = $args{'layer'};
		my $encap = $layer - 1;

		print "\t"x$encap,"Firewall {\n";

		for (0..1) {
			if ($summary_ref->[$_]->{'number'}) {
				print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."number: ", $summary_ref->[$_]->{'number'},"\n";
				if ($verbose && $summary_ref->[$_]->{'number'} < 50) {
					print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."name: ", "@{$summary_ref->[$_]->{'name'}}\n";
				}
			}
		}

		print "\t"x$encap,"}\n";
}

sub analyze_firewall {
		my %args = (
				'firewall' => undef,
				'layer' => 1,
				'verbose' => 0,
				@_,
		);

		my $fw = $args{'firewall'};
		my $layer = $args{'layer'};
		my $verbose = $args{'verbose'};

		clear_summary($firewall_summary);


		my @kw_family = qw(inet inet6 bridge any);
		my %family;
		my (@filter_ipv4,@filter_ipv6);
		my $ptn_filter = qr/(filter\s([\S]+)\s(\{((?:(?>[^{}]+)|(?3))*)\}))/;
		for (@kw_family) {
				my $ptn_family = qr/(family\s($_)\s(\{((?:(?>[^{}]+)|(?3))*)\}))/;
				if ($fw =~ /$ptn_family/) {
						$fw = $`.$';
						my @raw_filter = $4 =~ /$ptn_filter/g;
						my @filter_name = pickup_item(array=>\@raw_filter,step=>4,indexing=>2); 
						$family{$_} = \@filter_name; 
				}

		}
		push(@filter_ipv4,@{$family{'inet'}}) if defined($family{'inet'});
		push(@filter_ipv6,@{$family{'inet6'}}) if defined($family{'inet6'});
		if ($fw ne '') {
				my @raw_filter = $fw =~ /$ptn_filter/g;
				my @filter_name = pickup_item(array=>\@raw_filter,step=>4,indexing=>2); 
				push(@filter_ipv4,@filter_name);
		}


		$firewall_summary->[0]->{'number'} = @{$firewall_summary->[0]->{'name'}} = @filter_ipv4;
		$firewall_summary->[1]->{'number'} = @{$firewall_summary->[1]->{'name'}} = @filter_ipv6;


		show_summary(summary=>$firewall_summary,verbose=>$verbose,layer=>$layer);
}

1;
