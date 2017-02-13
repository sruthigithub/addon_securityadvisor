package Cpanel::Security::Advisor::Assessors::Apache;

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
use base 'Cpanel::Security::Advisor::Assessors';
use Cpanel::Config::Sources    ();
use Cpanel::HttpRequest        ();
use Cpanel::HttpUtils::Version ();
use Cpanel::SafeRun::Errors    ();
use Cpanel::Config::Httpd      ();
use Cpanel::Validate::Username ();
use Cpanel::GenSysInfo         ();
use Cpanel::DataStore          ();
use Cpanel::RestartSrv         ();

sub version {
    return '1.03';
}

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_apache_chroot();
    $self->_check_for_easyapache_build();
    $self->_check_for_eol_apache();
    $self->_check_for_symlink_protection();
    return 1;
}

sub estimated_runtime {

    # These checks have to connect out to the cpanel mirrors to verify the current version
    return 5;
}

sub _check_for_apache_chroot {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    if ( $security_advisor_obj->{'cpconf'}->{'jailapache'} ) {
        $security_advisor_obj->add_advice(
            {
                'key'  => 'Apache_jailed_apache_is_enabled',
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => $self->_lh->maketext('Jailed Apache is enabled'),
            }
        );
    }
    elsif ( -x '/usr/bin/cagefsctl' || -x '/usr/sbin/cagefsctl' ) {
        $security_advisor_obj->add_advice(
            {
                'key'  => 'Apache_cagefs_is_enabled',
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => $self->_lh->maketext('CageFS is enabled'),
            }
        );
    }
    else {

        $security_advisor_obj->add_advice(
            {
                'key'        => 'Apache_vhosts_not_segmented',
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => $self->_lh->maketext('Apache vhosts are not segmented or chroot()ed.'),
                'suggestion' => $self->_lh->maketext(
                    'Enable “Jail Apache” in the “[output,url,_1,Tweak Settings,_4,_5]” area, and change users to jailshell in the “[output,url,_2,Manage Shell Access,_4,_5]” area.  Consider a more robust solution by using “[output,url,_3,CageFS on CloudLinux,_4,_5]”',
                    $self->base_path('scripts2/tweaksettings?find=jailapache'),
                    $self->base_path('scripts2/manageshells'),
                    'https://go.cpanel.net/cloudlinux',
                    'target',
                    '_blank'
                ),
            }
        );
    }

    return 1;
}

sub _check_for_easyapache_build {
    my $self                 = shift;
    my $security_advisor_obj = $self->{'security_advisor_obj'};

    my $cpsources          = Cpanel::Config::Sources::loadcpsources();
    my $ea_update_server   = defined $cpsources->{'EASOURCES'} ? $cpsources->{'EASOURCES'} : $cpsources->{'HTTPUPDATE'};
    my $httprequest_obj    = Cpanel::HttpRequest->new( 'hideOutput' => 1 );
    my $latest_ea3_version = '';
    eval { $latest_ea3_version = $httprequest_obj->request( 'host' => $ea_update_server, 'url' => '/cpanelsync/easy/version_easy', 'protocol' => 0, ); };
    chomp($latest_ea3_version);

    my $installed_version = Cpanel::SafeRun::Errors::saferunallerrors( _get_httpd_path(), '-v' );
    $installed_version = $installed_version =~ /Cpanel::Easy::Apache v([\d.]+)/s ? $1 : '';

    if ( $latest_ea3_version && $installed_version && $latest_ea3_version ne $installed_version ) {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Apache_easyapache3_updates_available',
                'type'       => $Cpanel::Security::Advisor::ADVISE_WARN,
                'text'       => $self->_lh->maketext('EasyApache3 has updates available.'),
                'suggestion' => $self->_lh->maketext(
                    '[output,url,_1,EasyApache3,_2,_3] needs to be run periodically to update Apache, PHP and other public server functionality to the latest versions. Updates to EasyApache3 often fix security vulnernabilities in this software.',
                    $self->base_path('cgi/easyapache.pl?action=_pre_cpanel_sync_screen'),
                    'target',
                    '_blank'
                ),
            }
        );
    }
    return 1;
}

sub _check_for_eol_apache {
    my ($self) = @_;
    my $security_advisor_obj = $self->{'security_advisor_obj'};

    my $apache_version = Cpanel::HttpUtils::Version::get_httpd_version();
    if ( $apache_version =~ /^(1\.3|2\.0)/ ) {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Apache_is_eol',
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => $self->_lh->maketext('Your Apache version is EOL (End of Life)'),
                'suggestion' => $self->_lh->maketext(
                    "Apache v${apache_version} is End of Life (EOL), which means it is no longer updated, and security holes will not be patched. Run [output,url,_1,EasyApache,_2,_3] and choose a newer, supported version.",
                    $self->base_path('cgi/easyapache.pl?action=_pre_cpanel_sync_screen'),
                    'target',
                    '_blank'
                ),
            }
        );
    }
    return 1;
}

sub _check_for_symlink_protection {
    my ($self) = @_;
    my @protections;
    my @protections_issues;
    my $kernel_type = Cpanel::Security::Advisor::Assessors::get_running_kernel_type();
    my ($ruid) = ( grep { /ruid2_module/ } split( /\n/, Cpanel::SafeRun::Simple::saferun( _get_httpd_path(), '-M' ) ) );

    if ( $kernel_type eq "cloudlinux" ) {
        $self->_cloudlinux_symlink_protection($ruid);
    }
    elsif ( $kernel_type eq "grsec" ) {
        $self->_grsecurity_symlink_protection();
    }
    elsif ( $kernel_type eq "other" ) {
        $self->_centos_symlink_protection($ruid);
    }
    return 1;
}

sub _centos_symlink_protection {
    my $self                 = shift;
    my $ruid                 = shift;
    my $security_advisor_obj = $self->{'security_advisor_obj'};
    my $good                 = $Cpanel::Security::Advisor::ADVISE_GOOD;
    my $info                 = $Cpanel::Security::Advisor::ADVISE_INFO;
    my $warn                 = $Cpanel::Security::Advisor::ADVISE_WARN;
    my $bad                  = $Cpanel::Security::Advisor::ADVISE_BAD;
    my $httpd_binary         = Cpanel::LoadFile::loadfile( _get_httpd_path(), { 'binmode' => 1 } );
    my $rack911              = grep { /UnhardenedSymLinks/ } $httpd_binary;
    my $jailedapache         = $security_advisor_obj->{'cpconf'}->{'jailapache'};
    my $sysinfo              = Cpanel::GenSysInfo::run();

    my $is_ea4 = ( defined &Cpanel::Config::Httpd::is_ea4 && Cpanel::Config::Httpd::is_ea4() ) ? 1 : 0;
    my $bluehost_ea3 = ($is_ea4) ? 0 : grep { /SPT_DOCROOT/ } $httpd_binary;
    my $local_settings = ($is_ea4) ? Cpanel::DataStore::fetch_ref('/var/cpanel/conf/apache/local') : undef;
    my $bluehost_ea4 = ($is_ea4) ? ( exists $local_settings->{main}->{symlink_protect} && $local_settings->{main}->{symlink_protect}->{item}->{symlink_protect} eq 'On' ) : 0;

    if ($ruid) {
        if ($jailedapache) {
            $security_advisor_obj->add_advice(
                {
                    'key'  => 'Apache_symlink_protection_enabled',
                    'type' => $good,
                    'text' => $self->_lh->maketext('Apache Symlink Protection is enabled'),
                }
            );
        }
        else {
            $security_advisor_obj->add_advice(
                {
                    'key'        => 'Apache_mod_ruid2_is_loaded',
                    'type'       => $info,
                    'text'       => $self->_lh->maketext('Apache Symlink Protection: mod_ruid2 loaded in Apache'),
                    'suggestion' => $self->_lh->maketext(
                        "mod_ruid2 is enabled in Apache. To ensure that this aids in protecting from symlink attacks, Jailed Apache needs to be enabled. If this not set properly, you should see an indication in Security Advisor (this page) in the sections for “Apache vhosts are not segmented or chroot()ed” and “Users running outside of the jail”. If those are not present, your users should be properly jailed. Review [output,url,_1,Symlink Race Condition Protection,_2,_3] for further information.",
                        ($is_ea4) ? 'https://go.cpanel.net/EA4Symlink' : 'https://go.cpanel.net/apachesymlink',
                        'target',
                        '_blank'
                    ),
                }
            );
        }
    }
    if ( $bluehost_ea3 || $bluehost_ea4 ) {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Apache_bluehost_provided_symlink_protection',
                'type'       => $warn,
                'text'       => $self->_lh->maketext('Apache Symlink Protection: the Bluehost provided Apache patch is in effect'),
                'suggestion' => $self->_lh->maketext(
                    "It appears that the Bluehost provided Apache patch is being used to provide symlink protection. This is less than optimal. Please review [output,url,_1,Symlink Race Condition Protection,_2,_3].",
                    ($is_ea4) ? 'https://go.cpanel.net/EA4Symlink' : 'https://go.cpanel.net/apachesymlink',
                    'target',
                    '_blank'
                ),
            }
        );
    }
    if ($rack911) {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Apache_rack911_provided_symlink_protection',
                'type'       => $warn,
                'text'       => $self->_lh->maketext('Apache Symlink Protection: the Rack911 provided Apache patch is in effect'),
                'suggestion' => $self->_lh->maketext(
                    "It appears that the Rack911 provided Apache patch is being used to provide symlink protection. This is less than optimal. Please review [output,url,_1,Symlink Race Condition Protection,_2,_3].",
                    ($is_ea4) ? 'https://go.cpanel.net/EA4Symlink' : 'https://go.cpanel.net/apachesymlink',
                    'target',
                    '_blank',
                ),
            }
        );
    }
    if ( !($ruid) && !($rack911) && !($bluehost_ea3) && !($bluehost_ea4) && $sysinfo->{'rpm_dist_ver'} != 6 ) {    # if CentOS 6 is detected, defer to the Assessors::Symlinks
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Apache_no_symlink_protection',
                'type'       => $bad,
                'text'       => $self->_lh->maketext('No symlink protection detected'),
                'suggestion' => $self->_lh->maketext(
                    'You do not appear to have any symlink protection enabled on this server. You can protect against this in multiple ways. Please review the following [output,url,_1,documentation,_2,_3] to find a solution that is suited to your needs.',
                    ($is_ea4) ? 'https://go.cpanel.net/EA4Symlink' : 'https://go.cpanel.net/apachesymlink',
                    'target',
                    '_blank'
                ),
            }
        );
    }
    return 1;
}

sub _cloudlinux_symlink_protection {
    my $self                 = shift;
    my $ruid                 = shift;
    my $security_advisor_obj = $self->{'security_advisor_obj'};
    my $good                 = $Cpanel::Security::Advisor::ADVISE_GOOD;
    my $info                 = $Cpanel::Security::Advisor::ADVISE_INFO;
    my $warn                 = $Cpanel::Security::Advisor::ADVISE_WARN;
    my $bad                  = $Cpanel::Security::Advisor::ADVISE_BAD;
    my ( $sysctl_fs_enforce_symlinksifowner, $sysctl_fs_symlinkown_gid ) = (
        Cpanel::SafeRun::Simple::saferun( 'sysctl', '-n', 'fs.enforce_symlinksifowner' ),
        Cpanel::SafeRun::Simple::saferun( 'sysctl', '-n', 'fs.symlinkown_gid' )
    );
    chomp( $sysctl_fs_enforce_symlinksifowner, $sysctl_fs_symlinkown_gid );

    my $is_ea4 = ( defined &Cpanel::Config::Httpd::is_ea4 && Cpanel::Config::Httpd::is_ea4() ) ? 1 : 0;

    if ( -x '/usr/sbin/cagefsctl' ) {
        my $uncaged_user_count = grep {
            !/^\d+ disabled/

              # Some additional users that may be installed.
              && !/^(?:dovenull|polkitd)$/
              && !Cpanel::Validate::Username::reserved_username_check($_)
        } split( /\n/, Cpanel::SafeRun::Simple::saferun( '/usr/sbin/cagefsctl', '--list-disabled' ) );

        if ( $uncaged_user_count > 0 ) {
            $security_advisor_obj->add_advice(
                {
                    'key'        => 'Apache_symlink_protection_cagefs_disabled',
                    'type'       => $warn,
                    'text'       => $self->_lh->maketext('Apache Symlink Protection: Users with CloudLinux CageFS disabled'),
                    'suggestion' => $self->_lh->maketext(
                        "There appear to be users with cagefs disabled on this server. CageFS in combination with other features of Cloudlinux can further increase security. For further information see the [output,url,_1,CageFS Documentation,_2,_3] and the cPanel documentation on [output,url,_4,Symlink Race Condition Protection,_2,_3]. You have [output,strong,_5] uncaged users.",
                        'http://docs.cloudlinux.com/index.html?cagefs.html',
                        'target',
                        '_blank',
                        ($is_ea4) ? 'https://go.cpanel.net/EA4Symlink' : 'https://go.cpanel.net/apachesymlink',
                        "$uncaged_user_count"
                    ),
                }
            );
        }
        elsif ( !_is_cagefs_running() ) {
            $security_advisor_obj->add_advice(
                {
                    'key'        => 'Apache_cagefs_installed_but_not_running',
                    'type'       => $warn,
                    'text'       => $self->_lh->maketext('Apache Symlink Protection: CloudLinux CageFS is installed but not currently running'),
                    'suggestion' => $self->_lh->maketext(
                        "CageFS appears to be installed but is not currently running. CageFS adds filesystem level security to your users by isolating their filesystems from each other and many other parts of the system. For further information, see the [output,url,_1,CageFS Documentation,_2,_3].",
                        'http://docs.cloudlinux.com/index.html?cagefs.html',
                        'target',
                        '_blank'
                    ),
                }
            );
        }
        else {
            $security_advisor_obj->add_advice(
                {
                    'key'        => 'Apache_cagefs_running',
                    'type'       => $good,
                    'text'       => $self->_lh->maketext('Apache Symlink Protection: Cloudlinux CageFS protections are in effect'),
                    'suggestion' => $self->_lh->maketext('You are running CageFS. This provides filesystem level protections for your users and server.')

                }
            );
        }
    }
    if ( ($ruid) && ( ( $sysctl_fs_enforce_symlinksifowner !~ /1|2/ ) || ( $sysctl_fs_symlinkown_gid != 99 ) ) ) {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Apache_sysctl_problems_2',
                'type'       => $bad,
                'text'       => $self->_lh->maketext('Apache Symlink Protection: Problems with CloudLinux sysctl settings'),
                'suggestion' => $self->_lh->maketext(
                    "Your sysctl values appear to not be set appropriately for your Apache configuration. To resolve this, please see the documentation on [output,url,_1,SecureLinks,_2,_3]",
                    'http://docs.cloudlinux.com/index.html?securelinks.html',
                    'target',
                    '_blank'
                ),
            }
        );
    }
    elsif ( !($ruid) && ( ( $sysctl_fs_enforce_symlinksifowner != 1 ) || ( $sysctl_fs_symlinkown_gid != 99 ) ) ) {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Apache_sysctl_problems_2',
                'type'       => $bad,
                'text'       => $self->_lh->maketext('Apache Symlink Protection: Problems with CloudLinux sysctl settings'),
                'suggestion' => $self->_lh->maketext(
                    "Your sysctl values appear to not be set appropriately for your Apache configuration. To resolve this, please see the documentation on [output,url,_1,SecureLinks,_2,_3]",
                    'http://docs.cloudlinux.com/index.html?securelinks.html',
                    'target',
                    '_blank'
                ),
            }
        );
    }
    else {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Apache_symlink_protection_in_effect',
                'type'       => $good,
                'text'       => $self->_lh->maketext('Apache Symlink Protection: CloudLinux protections are in effect.'),
                'suggestion' => $self->_lh->maketext(
                    "You appear to have sufficient protections from Apache Symlink Attacks. If you have not already, consider increasing protection with [output,url,_1,CageFS,_2,_3]. For further information on symlink attack protection see our [output,url,_4,suggestions,_2,_3] on it.",
                    'http://docs.cloudlinux.com/index.html?cagefs.html',
                    'target',
                    '_blank',
                    ($is_ea4) ? 'https://go.cpanel.net/EA4Symlink' : 'https://go.cpanel.net/apachesymlink'
                ),
            }
        );

    }
    return 1;
}

sub _is_cagefs_running {
    my $self = shift;

    if ( Cpanel::RestartSrv::has_service_via_systemd('cagefs') ) {
        return ( Cpanel::SafeRun::Simple::saferun( '/usr/bin/systemctl', 'is-active', 'cagefs' ) eq 'active' ) ? 1 : 0;
    }
    else {
        return ( Cpanel::SafeRun::Simple::saferun( '/etc/init.d/cagefs', 'status' ) =~ /running/ ) ? 1 : 0;
    }

    return;
}

sub _grsecurity_symlink_protection {
    my $self                 = shift;
    my $security_advisor_obj = $self->{'security_advisor_obj'};
    my $good                 = $Cpanel::Security::Advisor::ADVISE_GOOD;
    my $info                 = $Cpanel::Security::Advisor::ADVISE_INFO;
    my $warn                 = $Cpanel::Security::Advisor::ADVISE_WARN;
    my $bad                  = $Cpanel::Security::Advisor::ADVISE_BAD;
    my ( $sysctl_kernel_grsecurity_symlinkown_gid, $sysctl_kernel_grsecurity_enforce_symlinksifowner ) = (
        Cpanel::SafeRun::Simple::saferunallerrors( 'sysctl', '-n', 'kernel.grsecurity.symlinkown_gid' ),
        Cpanel::SafeRun::Simple::saferunallerrors( 'sysctl', '-n', 'kernel.grsecurity.enforce_symlinksifowner' )
    );
    if ( ( $sysctl_kernel_grsecurity_symlinkown_gid =~ /unknown/ ) && ( $sysctl_kernel_grsecurity_enforce_symlinksifowner =~ /unknown/ ) ) {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Apache_grsecurity_does_not_have_sysctl_enabeled',
                'type'       => $warn,
                'text'       => $self->_lh->maketext('Apache Symlink Protection: Grsecruity does not have the sysctl option enabled'),
                'suggestion' => $self->_lh->maketext(
                    "It appears that the sysctl option may not have been selected for the grsec kernel. Due to this, it is not possible to verify the configuration of symlinkown_gid which is the gid of the Apache user that should not follow symlinks. This is usually 99 on cPanel servers. If you are confident that this is correct and do not wish to be able to easily verify your grsecurity kernel options, then you may disregard this message. Otherwise, please visit the [output,url,_1,Grsecurity Documentation,_2,_3] to learn more about enabling the sysctl option during kernel compilation.",
                    'http://en.wikibooks.org/wiki/Grsecurity/Configuring_and_Installing_grsecurity#Suggestions',
                    'target',
                    '_blank'
                ),
            }
        );
    }
    elsif (( $sysctl_kernel_grsecurity_symlinkown_gid != 99 )
        || ( $sysctl_kernel_grsecurity_enforce_symlinksifowner != 1 ) ) {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Apache_grsecurity_sysctl_values',
                'type'       => $bad,
                'text'       => $self->_lh->maketext('Apache Symlink Protection: Grsecurity sysctl values'),
                'suggestion' => $self->_lh->maketext(
                    "It seems that your sysctl keys, enforce_symlinksifowner, and symlinkown_gid, may not be configured correctly for a cPanel server. Typically, enforce_symlinksifowner is set to 1, and symlinkown_gid is set to 99 on a cPanel server. For further information, see the [output,url,_1,Grsecurity Documentation,_2,_3].",
                    'http://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options#Kernel-enforced_SymlinksIfOwnerMatch',
                    'target',
                    '_blank'
                ),
            }
        );
    }
    else {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Apache_grsecurity_protection_enabled',
                'type'       => $good,
                'text'       => $self->_lh->maketext('Apache Symlink Protection: You are well protected by grsecurity'),
                'suggestion' => $self->_lh->maketext("You appear to have sufficient protections from Apache Symlink Attacks"),
            }
        );
    }
    return 1;
}

my $httpd;

sub _get_httpd_path {
    return $httpd if defined $httpd;
    $httpd = '/usr/local/apache/bin/httpd';
    if ( defined &Cpanel::Config::Httpd::is_ea4 ) {
        if ( Cpanel::Config::Httpd::is_ea4() ) {
            require Cpanel::ConfigFiles::Apache;
            $httpd = Cpanel::ConfigFiles::Apache->new()->bin_httpd();
        }
    }
    return $httpd;
}

1;
