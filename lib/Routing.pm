#!/usr/bin/perl5.12 -w
##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 03/06/2012
##
##-----------------------------------------------------------------------

package Routing;
use strict;
use Exporter;
use vars qw(@ISA @EXPORT);
use AnalysisCommon;

@ISA = qw(Exporter);
@EXPORT = qw(
	analyze_routing
	match_routing
);

## output format for Routing summary, use array to ensure the output order
my $routing_summary = [
		{'summary' => "Protocols", 'number' => 0, 'name' => []},
		{'summary' => "BGP local-AS", 'name' => ''},
		{'summary' => "EBGP neighbor", 'number' => 0, 'name' => []},
		{'summary' => "IBGP neighbor", 'number' => 0, 'name' => []},
		{'summary' => "OSPF area", 'number' => 0, 'name' => []},
		{'summary' => "OSPF interfaces", 'number' => 0,'int' => {}},
		{'summary' => "static route", 'number' => 0,'name' => []},
];
## summary end

## show summary result for routing related parts
sub show_summary {
		my %args = (
				'summary' => undef,
				'protocols' => undef,
				'rtoptions' => undef,
				'verbose' => 0,
				'layer' => 1,
				@_,
		);
		my $summary_ref = $args{'summary'};
		my $protocols = $args{'protocols'};
		my $routingoptions = $args{'rtoptions'};
		my $verbose = $args{'verbose'};
		my $layer = $args{'layer'};
		my $encap = $layer - 1;

		print "\t"x$encap,"Routing {\n";

		## protocols
		if (%{$protocols}) {
				print "\t"x$layer,"$summary_ref->[0]->{'summary'}"." "."number: ", $summary_ref->[0]->{'number'},"\n";
				print "\t"x$layer,"$summary_ref->[0]->{'summary'}"." "."name: ", "@{$summary_ref->[0]->{'name'}}","\n";
				if ($summary_ref->[1]->{'name'}) {
					print "\t"x$layer,"$summary_ref->[1]->{'summary'}".": ", join(' ',$summary_ref->[1]->{'name'}),"\n";
				}
				for (2..4) {
					if ($summary_ref->[$_]->{'number'}) {
						print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."number: ", $summary_ref->[$_]->{'number'},"\n";
						print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."name: ", join(' ',@{$summary_ref->[$_]->{'name'}}), "\n";
					}

				}
				if ($summary_ref->[5]->{'number'}) {
					print "\t"x$layer,"$summary_ref->[5]->{'summary'}"." "."number: ", $summary_ref->[5]->{'number'},"\n";
					while (my ($key,$value) = each %{$summary_ref->[5]->{'int'}}) {
							print "\t"x$layer,"area $key: ",join(' ',@{$value}),"\n";
					}
				}
		}

		## routing-options static route 
		if (%{$routingoptions}) {
			if ($summary_ref->[6]->{'number'}) {
				print "\t"x$layer,"$summary_ref->[6]->{'summary'}"." "."number: ", $summary_ref->[6]->{'number'},"\n";
				print "\t"x$layer,"$summary_ref->[6]->{'summary'}"." "."name: ", "@{$summary_ref->[6]->{'name'}}","\n" if $verbose;
			}
		}


		print "\t"x$encap,"}\n";
}

## analyze the keywords under protocols, also put routing-options static route here 
sub analyze_routing {
		my %args = (
				'protocols' => undef,
				'rtoptions' => undef,
				'layer' => 1,
				'verbose' => 0,
				@_,
		);

		my $protocols_ref = $args{'protocols'};
		my $routingoptions_ref = $args{'rtoptions'};
		my $layer = $args{'layer'};
		my $verbose = $args{'verbose'};

		clear_summary($routing_summary);


		## Handle protocols
		$routing_summary->[0]->{'number'} = keys %{$protocols_ref};
		@{$routing_summary->[0]->{'name'}} = keys %{$protocols_ref};

		## BGP
		if (defined($protocols_ref->{"bgp"})) {
				my $bgp_context = $protocols_ref->{"bgp"};
				my $ptn_bgp_nbr = qr/(group\s([^\s]+)\s(\{((?:(?>[^{}]+)|(?3))*)\}))/;
				my @nbr_context = grep {/$ptn_bgp_nbr/} ($bgp_context =~ /$ptn_bgp_nbr/g);

				($routing_summary->[1]->{'name'}) = $bgp_context =~ /\Qlocal-as\E ([^;]+)/;

				for (@nbr_context) {
						if (/type external/) {
								push @{$routing_summary->[2]->{'name'}},(/neighbor ([^;]+)/,/\Qpeer-as\E ([^;]+)/);
						} elsif (/type internal/) {
								push @{$routing_summary->[3]->{'name'}},(/neighbor ([^;]+)/);
						}
				}
				$routing_summary->[2]->{'number'} = @{$routing_summary->[2]->{'name'}}/2;
				$routing_summary->[3]->{'number'} = @{$routing_summary->[3]->{'name'}};

		}

		## OSPF 
		if (defined($protocols_ref->{"ospf"})) {
				my $ptn_ospf_area = qr/(area\s([^\s]+)\s(\{((?:(?>[^{}]+)|(?3))*)\}))/;
				my @ospf_array = ($protocols_ref->{'ospf'} =~ /$ptn_ospf_area/g);
				my (@area_context,@area_name,%area_int);
				my $ospf_int_num = 0;
				for (my $i = 0; $i < @ospf_array; $i+=4) {
					push @area_context, $ospf_array[$i];
					push @area_name, $ospf_array[$i+1];
					@{$area_int{$ospf_array[$i+1]}} = ($ospf_array[$i+3] =~ /interface\s([^\s;]+)(?:;|\s)/g);
					$ospf_int_num += @{$area_int{$ospf_array[$i+1]}};
				}
				@{$routing_summary->[4]->{'name'}} = @area_name;
				$routing_summary->[4]->{'number'} = @area_name;
				%{$routing_summary->[5]->{'int'}} = %area_int;
				$routing_summary->[5]->{'number'} = $ospf_int_num;

		}

		## Handle routing-options 
		## static routes
		if (defined($routingoptions_ref->{'static'})) {
				## Do not use recursive match since sometimes static routes don't have {}
				my $ptn_static_route = qr/route\s+([\S]+)\s+/;
				@{$routing_summary->[6]->{'name'}} = ($routingoptions_ref->{'static'}=~ /$ptn_static_route/g);
				$routing_summary->[6]->{'number'} = @{$routing_summary->[6]->{'name'}};

		}

		show_summary(summary=>$routing_summary,protocols=>$protocols_ref,rtoptions=>$routingoptions_ref,verbose=>$verbose,layer=>$layer);
		get_inactive_item($protocols_ref->{"bgp"}) if (defined($protocols_ref->{"bgp"}));
		get_inactive_item($protocols_ref->{"ospf"}) if (defined($protocols_ref->{"ospf"}));
		get_inactive_item($routingoptions_ref->{"static"}) if (defined($routingoptions_ref->{"static"}));
}

sub match_routing {

}

1;
