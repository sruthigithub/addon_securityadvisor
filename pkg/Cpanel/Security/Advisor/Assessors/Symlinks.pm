package Cpanel::Security::Advisor::Assessors::Symlinks;

# Copyright (c) 2016, cPanel, Inc.
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
use warnings;

use Lchown ();

use Cpanel::TempFile   ();
use Cpanel::GenSysInfo ();

use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_symlink_kernel_patch;

    return 1;
}

sub _enforcing_symlink_ownership {
    my $self = shift;

    my @sysctls = qw(
      /proc/sys/kernel/grsecurity/enforce_symlinksifowner
      /proc/sys/fs/enforce_symlinksifowner
    );

    foreach my $sysctl (@sysctls) {
        if ( -e $sysctl ) {
            return 1;
        }
    }

    return 0;
}

sub _symlink_enforcement_gid {
    my $self = shift;

    my @sysctls = qw(
      /proc/sys/kernel/grsecurity/symlinkown_gid
      /proc/sys/fs/symlinkown_gid
    );

    foreach my $sysctl (@sysctls) {
        if ( -e $sysctl ) {
            open my $fh, q{<}, $sysctl or die $!;
            my $val = <$fh>;
            close $fh;
            chomp $val;
            return int $val;
        }
    }

    return undef;
}

sub _check_for_symlink_kernel_patch {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    my $sysinfo = Cpanel::GenSysInfo::run();

    #
    # This test only pertains to RHEL/CentOS 6.
    #
    return 1 unless $sysinfo->{'rpm_dist_ver'} == 6;

    #
    # If a grsecurity kernel is not detected, then we should recommend that
    # the administrator install one.
    #
    unless ( $self->_enforcing_symlink_ownership() ) {
        $self->add_bad_advice(
            'key'        => q{Symlinks_no_kernel_support_for_ownership_attacks_1},
            'text'       => $self->_lh->maketext('Kernel does not support the prevention of symlink ownership attacks.'),
            'suggestion' => $self->_lh->maketext('You do not appear to have any symlink protection enabled through a properly patched kernel on this server, which provides additional protect beyond those solutions employed in userland. Please review the following documentation to learn how to apply this protection.'),
        );

        return 1;
    }

    my $gid = $self->_symlink_enforcement_gid();

    unless ( defined $gid ) {
        $self->add_bad_advice(
            'key'        => q{Symlinks_no_kernel_support_for_ownership_attacks_2},
            'text'       => $self->_lh->maketext('Kernel does not support the prevention of symlink ownership attacks.'),
            'suggestion' => $self->_lh->maketext('You do not appear to have any symlink protection enabled through a properly patched kernel on this server, which provides additional protect beyond those solutions employed in userland. Please review the following documentation to learn how to apply this protection.'),
        );

        return 1;
    }

    my $shadow = '/etc/shadow';
    my $tmpobj = Cpanel::TempFile->new;
    my $dir    = $tmpobj->dir;
    my $link   = "$dir/shadow";

    chmod 0755, $dir;

    symlink $shadow => $link or die "Unable to symlink() $shadow to $link: $!";

    Lchown::lchown( $gid, $gid, $link ) or die "Unable to lchown() $link: $!";

    {
        local $) = $gid;

        if ( open my $fh, '<', $link ) {
            $self->add_bad_advice(
                'key'        => q{Symlinks_protection_not_enabled_for_centos6},
                'text'       => $self->_lh->maketext('Kernel symlink protection is not enabled for CentOS 6.'),
                'suggestion' => $self->_lh->maketext('You do not appear to have any symlink protection enabled through a properly patched kernel on this server, which provides additional protect beyond those solutions employed in userland. Please review the following documentation to learn how to apply this protection.'),
            );

            close $fh;
        }
        else {
            $self->add_good_advice(
                'key'  => q{Symlinks_protection_enabled_for_centos6},
                'text' => $self->_lh->maketext('Kernel symlink protection is enabled for CentOS 6.'),
            );
        }
    }

    return 1;
}

1;
