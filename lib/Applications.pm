#!/usr/bin/perl5.12 -w
##-----------------------------------------------------------------------
##
## Author: Michael Zhou, routesf@gmail.com 03/06/2012
##
##-----------------------------------------------------------------------

package Applications;
use strict;
use Exporter;
use vars qw(@ISA @EXPORT);
use AnalysisCommon;

@ISA = qw(Exporter);
@EXPORT = qw(
	analyze_applications
	match_applications
);

## output format for application summary, use array to ensure the output order
my $applications_summary = [
		{'summary' => "application", 'number' => 0, 'name' => []},
		{'summary' => "application udp", 'number' => 0, 'name' => []},
		{'summary' => "application tcp", 'number' => 0, 'name' => []},
		{'summary' => "application-set", 'number' => 0, 'name' => []},
];
## summary end

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

		print "\t"x$encap,"Applications {\n";
		for (@$summary_ref) {
			if ($_->{'number'}) {
				print "\t"x$layer,"$_->{'summary'}"." "."number: ", $_->{'number'},"\n";
				if ($verbose && $_->{'number'} < 50) {
					print "\t"x$layer,"$_->{'summary'}"." "."name: ", "@{$_->{'name'}}\n";
				}
			}

		}
		print "\t"x$encap,"}\n";
}
sub analyze_applications {
		my %args = (
				'applications' => undef,
				'layer' => 1,
				'verbose' => 0,
				@_,
		);

		my $app = $args{'applications'};
		my $layer = $args{'layer'};
		my $verbose = $args{'verbose'};

		clear_summary($applications_summary);

		## Handle applications 


				my $ptn_application = qr/(application\s([^\s]+)\s(\{((?:(?>[^{}]+)|(?3))*)\}))/;
				my $ptn_application_set = qr/(application-set\s([^\s]+)\s(\{((?:(?>[^{}]+)|(?3))*)\}))/;

				## application
				my @ary_application = ($app =~ /$ptn_application/g); 
				my (@app_udp_name,@app_udp_context,@app_tcp_name,@app_tcp_context);
				for (my $i = 0; $i < @ary_application; $i+=4) {
						if ($ary_application[$i+3] =~ /protocol udp/) {
							push @app_udp_context, $ary_application[$i];
							push @app_udp_name, $ary_application[$i+1];
						} elsif ($ary_application[$i+3] =~ /protocol tcp/) {
							push @app_tcp_context, $ary_application[$i];
							push @app_tcp_name, $ary_application[$i+1];
						}
				}
				$applications_summary->[0]->{'number'} = @{$applications_summary->[0]->{'name'}} = (@app_udp_name,@app_tcp_name);
				$applications_summary->[1]->{'number'} = @{$applications_summary->[1]->{'name'}} = @app_udp_name;
				$applications_summary->[2]->{'number'} = @{$applications_summary->[2]->{'name'}} = @app_tcp_name;


				## application-set
				my @ary_application_set = ($app =~ /$ptn_application_set/g); 
				my (@ary_application_set_name,@ary_application_set_context);
				for (my $i = 0; $i < @ary_application_set; $i+=4) {
						push @ary_application_set_context, $ary_application_set[$i];
						push @ary_application_set_name, $ary_application_set[$i+1];
				}
				$applications_summary->[3]->{'number'} = @{$applications_summary->[3]->{'name'}} = @ary_application_set_name;

				show_summary(summary=>$applications_summary,verbose=>$verbose,layer=>$layer);
				#get_inactive_item($app);


}

sub match_applications {

}
1;
