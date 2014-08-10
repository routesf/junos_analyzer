#!/usr/bin/perl5.12 -w
##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 08/06/2013
##
##-----------------------------------------------------------------------

package Misc;
use strict;
use Exporter;
use vars qw(@ISA @EXPORT);
use AnalysisCommon;

@ISA = qw(Exporter);
@EXPORT = qw(
	analyze_basic
);

## output format for basic summary, use array to ensure the output order
my $basic_summary = [
		{'summary' => "Device", 'name' => ''},
		{'summary' => "system login user", 'number' => 0, 'name' => []},
		{'summary' => "reth interface", 'number' => 0, 'name' => []},
		{'summary' => "GE interface", 'number' => 0, 'name' => []},
		{'summary' => "XE interface", 'number' => 0, 'name' => []},
		{'summary' => "AE interface", 'number' => 0, 'name' => []},
		{'summary' => "sub interface", 'number' => 0, 'name' => {}},
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

		print "\t"x$encap,"Summary {\n";

		print "\t"x$layer,"$summary_ref->[0]->{'summary'}"." "."info: ", $summary_ref->[0]->{'name'},"\n";
		for (1..5) {
			if ($summary_ref->[$_]->{'number'}) {
				print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."number: ", $summary_ref->[$_]->{'number'},"\n";
				if ($verbose && $summary_ref->[$_]->{'number'} < 50) {
					print "\t"x$layer,"$summary_ref->[$_]->{'summary'}"." "."name: ", "@{$summary_ref->[$_]->{'name'}}\n";
				}
			}
		}
		## Don's show sub-interface name
		print "\t"x$layer,"$summary_ref->[6]->{'summary'}"." "."number: ", $summary_ref->[6]->{'number'},"\n";

		print "\t"x$encap,"}\n";
}

sub analyze_basic {
		my %args = (
				'cfg' => undef,
				'rest' => undef,
				'layer' => 1,
				'verbose' => 0,
				@_,
		);

		my $cfg_ref = $args{'cfg'};
		my $rest = $args{'rest'};
		my $layer = $args{'layer'};
		my $verbose = $args{'verbose'};

		clear_summary($basic_summary);

		## check the version info
		my $dut_version = '';
		my @apply_group = ();
		my @hostname = ();
		my @user = ();

		if ($rest =~ /version ([^;]+);/) {
				$dut_version = $1;
		}
		if ($rest =~ /apply-groups ([^;]+);/) {
				my $group = $1;
				if ($group =~ /\[/) {
					$group =~ s/\A\[\s+(.*)\s+\]\z/$1/;
					@apply_group = split(/ /,$group);
				} else {
					push(@apply_group,$group);
				}
		}


		my $ptn_user = qr/(user\s([^\s]+)\s(\{((?:(?>[^{}]+)|(?3))*)\}))/;
		## system 
		if (defined($cfg_ref->{"system"})) {
				my ($system_ref,$system_rest) = split_file(data=>$cfg_ref->{'system'},save=>0);
				if ($system_rest =~ /host-name ([^;]+);/) {
						push(@hostname,$1);
				}
				if (defined $system_ref->{'login'}) {
						my @raw_user = $system_ref->{'login'} =~ /$ptn_user/g;
						push(@user,pickup_item(array=>\@raw_user,step=>4,indexing=>2));

				}
		}
		## groups
		if (defined($cfg_ref->{"groups"})) {
				my $groups_ref = split_file(data=>$cfg_ref->{'groups'},save=>0);
				my %groups_hash_ref;
				while (my ($key,$value) = each %{$groups_ref}) {
						push(@hostname,$value =~ /host-name ([^;]+);/g);
						$groups_hash_ref{$key} = split_file(data=>$value,save=>0);
						if (defined($groups_hash_ref{$key}->{'system'})) {
								my $groups_system_ref = split_file(data=>$groups_hash_ref{$key}->{'system'},save=>0);
								if (defined($groups_system_ref->{'login'})) {
										my @raw_user_group = $groups_system_ref->{'login'} =~ /$ptn_user/g;
										push(@user,pickup_item(array=>\@raw_user_group,step=>4,indexing=>2));
								}
						}
				}
		}

		my %hash_ct;
		my $name;
		@hostname = grep {++$hash_ct{$_} == 1} @hostname;
		if (@hostname == 2) {
				$name = join(':',@hostname);
		} else {
				$name = $hostname[0];

		}
		
		my $mode;
		if (defined($cfg_ref->{"chassis"})) {
				my $ptn_cluster = qr/(cluster\s(\{((?:(?>[^{}]+)|(?2))*)\}))/;
				my $ptn_rg = qr/(redundancy\-group\s([^\s]+)\s(\{((?:(?>[^{}]+)|(?3))*)\}))/;
				my @rg_context;
				if ($cfg_ref->{'chassis'} =~ /$ptn_cluster/) {
						@rg_context = grep {/$ptn_rg/} ($3 =~ /$ptn_rg/g);
						if (@rg_context == 2) {
								$mode = 'HA-Active/Passive';
						} elsif (@rg_context > 2) { 
								$mode = 'HA-Active/Active';
						}

				} else {
						$mode = 'Standalone';
				}
		} else {
				$mode = 'Standalone';
		}


		## interfaces
		my (@int_reth,@int_ge,@int_xe,@int_ae);
		my %int_sub;
		if (defined($cfg_ref->{"interfaces"})) {
				my $ptn_unit = qr/(unit\s([^\s]+)\s(\{((?:(?>[^{}]+)|(?3))*)\}))/;
				my $int_ref = split_file(data=>$cfg_ref->{'interfaces'},save=>0);
				while (my ($key,$value) = each %{$int_ref}) {
						if ($key =~ /reth/) {
								push(@int_reth,$key);
						} elsif ($key =~ /ge/) {
								push(@int_ge,$key);
						} elsif ($key =~ /xe/) {
								push(@int_xe,$key);
						} elsif ($key =~ /ae/) {
								push(@int_ae,$key);
						}
						my @raw_unit = ($value =~ /$ptn_unit/g);
						if (@raw_unit) {
								my @subint = pickup_item(array=>\@raw_unit,step=>4,indexing=>2);
								$int_sub{$key} = \@subint;
						}
				}

		}
		my $subint_num = 0;
		for (values %int_sub) {
				$subint_num += @{$_};
		}
		$basic_summary->[0]->{'name'} = join(' ',($name,$mode,$dut_version));
		$basic_summary->[1]->{'number'} = @{$basic_summary->[1]->{'name'}} = @user;
		$basic_summary->[2]->{'number'} = @{$basic_summary->[2]->{'name'}} = @int_reth;
		$basic_summary->[3]->{'number'} = @{$basic_summary->[3]->{'name'}} = @int_ge;
		$basic_summary->[4]->{'number'} = @{$basic_summary->[4]->{'name'}} = @int_xe;
		$basic_summary->[5]->{'number'} = @{$basic_summary->[5]->{'name'}} = @int_ae;
		$basic_summary->[6]->{'number'} = $subint_num;
		%{$basic_summary->[6]->{'name'}} = %int_sub;


		show_summary(summary=>$basic_summary,verbose=>$verbose,layer=>$layer);
}

1;
