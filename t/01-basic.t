#!/usr/bin/perl

use warnings;
use strict;
use Test::More tests => 4;

use POE;
use POE::Component::Resolver qw(AF_INET AF_INET6);

my $r4 = POE::Component::Resolver->new(
	max_resolvers => 1,
	af_order      => [ AF_INET ],
);

my $r6 = POE::Component::Resolver->new(
	max_resolvers => 1,
	af_order      => [ AF_INET6 ],
);

my $r46 = POE::Component::Resolver->new(
	max_resolvers => 1,
	af_order      => [ AF_INET, AF_INET6 ],
);

my $r64 = POE::Component::Resolver->new(
	max_resolvers => 1,
	af_order      => [ AF_INET6, AF_INET ],
);

my $host = 'ipv6-test.com';
my $tcp  = getprotobyname("tcp");

POE::Session->create(
	inline_states => {
		_start => sub {
			$r4->resolve(
				host    => $host,
				service => 'http',
				hints   => { protocol => $tcp },
				misc    => [ AF_INET ],
			) or die $!;

			$r6->resolve(
				host    => $host,
				service => 'http',
				hints   => { protocol => $tcp },
				misc    => [ AF_INET6 ],
			) or die $!;

			$r46->resolve(
				host    => $host,
				service => 'http',
				hints   => { protocol => $tcp },
				misc    => [ AF_INET, AF_INET6 ],
			) or die $!;

			$r64->resolve(
				host    => $host,
				service => 'http',
				hints   => { protocol => $tcp },
				misc    => [ AF_INET6, AF_INET ],
			) or die $!;
		},

		resolver_response => sub {
			my ($error, $addresses, $request) = @_[ARG0..ARG2];

			my $expected_families = $request->{misc};

			my @got_families = map { $_->{family} } @$addresses;

			my $i = $#got_families;
			while ($i--) {
				splice(@got_families, $i, 1) if (
					$got_families[$i] == $got_families[$i+1]
				);
			}

			is_deeply(
				\@got_families,
				$expected_families,
				"address families are as expected",
			);
		},
	}
);

POE::Kernel->run();
