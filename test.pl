#!/usr/bin/perl

use warnings;
use strict;

use lib qw(./lib);
use POE;
use POE::Component::Resolver qw(AF_INET AF_INET6);

my $r = POE::Component::Resolver->new(
	max_resolvers => 8,
	af_order => [ AF_INET, AF_INET6 ],
);

my @hosts = qw(
	ipv6-test.com
);

my $tcp = getprotobyname("tcp");

POE::Session->create(
	inline_states => {
		_start => sub {
			foreach my $host (@hosts) {
				$r->resolve(
					host    => $host,
					service => "http",
					event   => "got_response",
					hints   => { protocol => $tcp },
				) or die $!;
			}
		},

		_stop => sub { print "client session stopped\n" },

		got_response => sub {
			my ($error, $addresses, $request) = @_[ARG0..ARG2];
			use YAML; print YAML::Dump(
				{
					error => $error,
					addr => $addresses,
					req => $request,
				}
			);
		},
	}
);

POE::Kernel->run();
