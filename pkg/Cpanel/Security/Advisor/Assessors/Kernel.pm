package Cpanel::Security::Advisor::Assessors::Kernel;

# Copyright 2017, cPanel, Inc.
# All rights reserved.
# http://cpanel.net
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the owner nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL  BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use base 'Cpanel::Security::Advisor::Assessors';
use Cpanel::SafeRun::Errors ();
use Cpanel::JSON            ();
use Cpanel::Kernel          ();
use Cpanel::OSSys::Env      ();
use Cpanel::Version         ();
use Cpanel::RPM             ();
use Cpanel::Logger          ();
use Cpanel::DIp::MainIP     ();
use Cpanel::NAT             ();
use HTTP::Tiny              ();

our $KC_CP_VERSION = q{11.63};
our $KC_VERIFY_URL = q{https://verify.cpanel.net};
our $KC_M2_URL     = q{manage2.cpanel.net};
if ( Cpanel::Logger::is_sandbox() ) {
    $KC_VERIFY_URL = q{http://cody.verify.manage.devel.cpanel.net};
    $KC_M2_URL     = q{swaaat.manage2.manage.devel.cpanel.net};
}

my $kc_kernelversion = kcare_kernel_version("uname");

sub version {
    return '1.03';
}

sub generate_advice {
    my ($self) = @_;

    # support for integrated KerneCare purchase/install is supported in 11.64 and above
    if ( Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '>=', $KC_CP_VERSION ) ) {
        $self->_suggest_kernelcare;
    }

    $self->_check_for_kernel_version;

    return 1;
}

sub _suggest_kernelcare {
    my ($self) = @_;

    my $environment  = Cpanel::OSSys::Env::get_envtype();
    my $manage2_data = _get_manage2_kernelcare_data();
    my $rpm          = Cpanel::RPM->new();

    if (    not $rpm->has_rpm(q{kernelcare})
        and not( $environment eq 'virtuozzo' || $environment eq 'lxc' )
        and not $manage2_data->{'disabled'} ) {

        my $label_text     = 'Upgrade to KernelCare.';
        my $contact_method = '';
        my $target         = '_parent';
        my $url_alt_text   = $label_text;
        my $url_to_use     = '../../../scripts12/purchase_kernelcare_init';

        # check to see this IP has a valid license even if it is not installed
        if ( _verify_kernelcare_license() ) {
            $label_text   = 'Valid KernelCare License Found, but KernelCare is Not Installed.';
            $url_alt_text = 'Click to install';
            $url_to_use   = '../../../scripts12/purchase_kernelcare_completion?order_status=success';
            $self->add_bad_advice(
                'key'        => 'Kernel_kernelcare_valid_license_but_not_installed',
                'text'       => [$label_text],
                'suggestion' => $self->_lh->maketext( 'KernelCare provides an easy, effortless way of keeping your operating system kernel up to date without needing to reboot your server. A valid license has already been purchased. [_1] [output,url,_2,_3,_4,_5].', $contact_method, $url_to_use, $url_alt_text, 'target', $target, ),
            );
        }
        else {
            if ( $manage2_data->{'url'} ne '' ) {
                $url_to_use = $manage2_data->{'url'};
            }
            elsif ( $manage2_data->{'email'} ne '' ) {
                $target         = '_blank';
                $url_to_use     = 'mailto:' . $manage2_data->{'email'};
                $contact_method = 'For more information,';
                $url_alt_text   = 'email your provider';
            }
            $self->add_warn_advice(
                'key'        => 'Kernel_kernelcare_purchase',
                'text'       => [$label_text],
                'suggestion' => $self->_lh->maketext( 'KernelCare provides an easy, effortless way of keeping your operating system kernel up to date without needing to reboot your server. [_1] [output,url,_2,_3,_4,_5].', $contact_method, $url_to_use, $url_alt_text, 'target', $target, ),
            );

        }
    }

    return 1;
}

sub _verify_kernelcare_license {
    my $mainserverip = Cpanel::NAT::get_public_ip( Cpanel::DIp::MainIP::getmainserverip() );
    my $verify_url   = sprintf( "%s/ipaddrs.cgi?ip=%s", $KC_VERIFY_URL, $mainserverip );
    my $response     = HTTP::Tiny->new->get($verify_url);
    local $@;
    my $results = eval { Cpanel::JSON::Load( $response->{'content'} ) };
    die $@ if $@;

    my $verified;
    foreach my $current ( @{ $results->{'current'} } ) {
        if ( $current->{'package'} eq q{CPDIRECT-MONTHLY-KERNELCARE} and $current->{'product'} eq q{KernelCare} and $current->{'status'} eq 1 and $current->{'valid'} eq 1 ) {
            ++$verified;
            last;
        }
    }
    return $verified;
}

sub _get_manage2_kernelcare_data {
    my $companyfile = q{/var/cpanel/companyid};
    my $cid         = q{};
    if ( open my $fh, "<", $companyfile ) {
        $cid = <$fh>;
        chomp $cid;
        close $fh;
    }

    my $url = sprintf( 'https://%s/kernelcare.cgi?companyid=%d', $KC_M2_URL, $cid );
    my $raw_resp = HTTP::Tiny->new( 'timeout' => 10 )->get($url);
    my $json_resp;

    if ( $raw_resp->{'success'} ) {
        eval { $json_resp = Cpanel::JSON::Load( $raw_resp->{'content'} ) };

        if ($@) {
            $json_resp = { disabled => 0, url => '', email => '' };
        }
    }
    else {
        $json_resp = { disabled => 0, url => '', email => '' };
    }

    # These are useful for testing; uncomment as needed to force behavior.
    # $json_resp = { disabled => 1, url => '', email => '' };
    # $json_resp = { disabled => 0, url => 'http://tester.com', email => '' };
    # $json_resp = { disabled => 0, url => '', email => 'test@tester.com' };

    return $json_resp;
}

sub _check_for_kernel_version {
    my ($self) = @_;

    my %kernel_update = kernel_updates();
    my @kernel_update = ();
    if ( ( keys %kernel_update ) ) {
        foreach my $update ( keys %kernel_update ) {
            unshift( @kernel_update, $kernel_update{$update} );
        }
    }

    my $boot_kernelversion    = Cpanel::Kernel::get_default_boot_version();
    my $running_kernelversion = Cpanel::Kernel::get_running_version();
    my $environment           = Cpanel::OSSys::Env::get_envtype();

    if ( $running_kernelversion =~ m/\.(?:noarch|x86_64|i.86).+$/ ) {
        $self->add_info_advice(
            'key'  => 'Kernel_can_not_check',
            'text' => $self->_lh->maketext( 'Custom kernel version cannot be checked to see if it is up to date: [_1]', $running_kernelversion )
        );
    }
    elsif ( ( $environment eq 'virtuozzo' ) || ( $environment eq 'lxc' ) ) {
        $self->add_info_advice(
            'key'  => 'Kernel_unsupported_environment',
            'text' => $self->_lh->maketext('Kernel updates are not supported on this virtualization platform. Be sure to keep the host’s kernel up to date.')
        );
    }
    elsif ( (@kernel_update) && ($kc_kernelversion) ) {
        if ( kcare_kernel_version("check") eq "New version available" ) {
            $self->add_bad_advice(
                'key'  => 'Kernel_kernelcare_update_available',
                'text' => $self->_lh->maketext(
                    'Kernel patched with KernelCare, but out of date. running kernel: [_1], most recent kernel: [list_and,_2]',
                    $kc_kernelversion,
                    \@kernel_update,
                ),
                'suggestion' => $self->_lh->maketext('This can be resolved either by running ’/usr/bin/kcarectl --update’ from the command line to begin an update of the KernelCare kernel version, or by running ’yum update’ from the command line and rebooting the system.'),
            );
        }
        else {
            $self->add_info_advice(
                'key'  => 'Kernel_waiting_for_kernelcare_update',
                'text' => $self->_lh->maketext(
                    'Kernel patched with KernelCare, but awaiting further updates. running kernel: [_1], most recent kernel: [list_and,_2]',
                    $kc_kernelversion,
                    \@kernel_update,
                ),
                'suggestion' => $self->_lh->maketext('The kernel will likely be patched to the current version within the next few days. If this delay is unacceptable, update the system’s software by running ’yum update’ from the command line and reboot the system.'),
            );
        }
    }
    elsif ( (@kernel_update) ) {
        $self->add_bad_advice(
            'key'  => 'Kernel_outdated',
            'text' => $self->_lh->maketext(
                'Current kernel version is out of date. running kernel: [_1], most recent kernel: [list_and,_2]',
                $running_kernelversion,
                \@kernel_update,
            ),
            'suggestion' => $self->_lh->maketext('Update the system’s software by running ’yum update’ from the command line and reboot the system.'),
        );
    }
    elsif ($kc_kernelversion) {
        $self->add_good_advice(
            'key'  => 'Kernel_kernelcare_is_current',
            'text' => $self->_lh->maketext( 'KernelCare is installed and current running kernel version is up to date: [_1]', $kc_kernelversion )
        );
    }
    elsif ( ( $running_kernelversion ne $boot_kernelversion ) ) {
        $self->add_bad_advice(
            'key'  => 'Kernel_boot_running_mismatch',
            'text' => $self->_lh->maketext(
                'Current kernel version does not match the kernel version for boot. running kernel: [_1], boot kernel: [_2]',
                $running_kernelversion,
                $boot_kernelversion
            ),
            'suggestion' => $self->_lh->maketext(
                'Reboot the system in the "[output,url,_1,Graceful Server Reboot,_2,_3]" area. Check the boot configuration in grub.conf if the new kernel is not loaded after a reboot.',
                $self->base_path('scripts/dialog?dialog=reboot'),
                'target',
                '_blank'
            ),
        );
    }
    else {
        $self->add_good_advice(
            'key'  => 'Kernel_running_is_current',
            'text' => $self->_lh->maketext( 'Current running kernel version is up to date: [_1]', $running_kernelversion )
        );
    }

    return 1;
}

sub kernel_updates {
    my %kernel_update;
    my @args         = qw(yum -d 0 info updates kernel);
    my @yum_response = Cpanel::SafeRun::Errors::saferunnoerror(@args);
    my ( $rpm, $arch, $version, $release );

    foreach my $element ( 0 .. $#yum_response ) {
        $rpm     = ( split( /:/, $yum_response[$element] ) )[1] if ( ( $yum_response[$element] =~ m/^Name/ ) );
        $arch    = ( split( /:/, $yum_response[$element] ) )[1] if ( ( $yum_response[$element] =~ m/^Arch/ ) );
        $version = ( split( /:/, $yum_response[$element] ) )[1] if ( ( $yum_response[$element] =~ m/^Version/ ) );
        $release = ( split( /:/, $yum_response[$element] ) )[1] if ( ( $yum_response[$element] =~ m/^Release/ ) );
        if ( ( ($rpm) && ($arch) && ($version) && ($release) ) ) {
            s/\s//g foreach ( $rpm, $arch, $version, $release );
            if ( $kc_kernelversion ne ( $version . "-" . $release . "." . $arch ) && $kc_kernelversion ne ( $version . "-" . $release ) ) {
                $kernel_update{ $rpm . " " . $version . "-" . $release } = $version . "-" . $release . "." . $arch;
                $rpm                                                     = undef;
                $arch                                                    = undef;
                $version                                                 = undef;
                $release                                                 = undef;
            }
        }
    }

    return %kernel_update;
}    # end of sub

sub kcare_kernel_version {
    my @args;
    my $kc_response = "";

    if ( -f "/usr/bin/kcarectl" ) {
        @args = ( "/usr/bin/kcarectl", "--" . "$_[0]" );
        $kc_response = Cpanel::SafeRun::Errors::saferunnoerror(@args);
        $kc_response =~ s/\+$//;
        chomp $kc_response;
    }

    return $kc_response;
}

1;

__END__
