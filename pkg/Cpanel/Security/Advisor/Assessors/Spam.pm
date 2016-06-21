package Cpanel::Security::Advisor::Assessors::Spam;

# Copyright (c) 2013, cPanel, Inc.
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
use Cpanel::LoadFile ();

use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_nobody_tracking();

    return 1;
}

sub _check_for_nobody_tracking {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    if ( $security_advisor_obj->{'cpconf'}->{'nobodyspam'} ) {
        $security_advisor_obj->add_advice(
            {
                'key'  => 'Spam_user_nobody_can_not_permitted_to_send_email',
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => $self->_lh->maketext('The pseudo-user “nobody” is not permitted to send email.'),
            }
        );
    }
    else {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Spam_user_nobody_can_send_email',
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => $self->_lh->maketext('The pseudo-user “nobody” is permitted to send email.'),
                'suggestion' => $self->_lh->maketext(
                    'Enable “Prevent "nobody" from sending mail” in the “[output,url,_1,Tweak Settings,_2,_3]” area',
                    $self->base_path('scripts2/tweaksettings?find=nobodyspam'),
                    'target',
                    '_blank'
                ),
            }
        );
    }

    if ( -e '/var/cpanel/smtpgidonlytweak' ) {
        $security_advisor_obj->add_advice(
            {
                'key'  => 'Spam_outbound_smtp_restricted',
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => $self->_lh->maketext('Outbound SMTP connections are restricted.'),
            }
        );

    }
    elsif ( _csf_has_option( 'SMTP_BLOCK', '1' ) ) {
        $security_advisor_obj->add_advice(
            {
                'key'  => 'Spam_smtp_block_enabled',
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => $self->_lh->maketext('CSF has SMTP_BLOCK enabled.'),
            }
        );

    }
    else {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Spam_smtp_unrestricted',
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => $self->_lh->maketext('Outbound SMTP connections are unrestricted.'),
                'suggestion' => $self->_lh->maketext(
                    'Enable SMTP Restrictions in the “[output,url,_1,SMTP Restrictions,_2,_3]” area',
                    $self->base_path('scripts2/smtpmailgidonly'),
                    'target',
                    '_blank'
                ),

            }
        );
    }

    if ( -e '/var/cpanel/config/email/query_apache_for_nobody_senders' ) {
        $security_advisor_obj->add_advice(
            {
                'key'  => 'Spam_apache_queried_for_sender',
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => $self->_lh->maketext('Apache is being queried to determine the actual sender when mail originates from the “nobody” pseudo-user.'),
            }
        );
    }
    else {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'Spam_apache_not_queried_for_sender',
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => $self->_lh->maketext('Apache is not being queried to determine the actual sender when mail originates from the “nobody” pseudo-user.'),
                'suggestion' => $self->_lh->maketext(
                    'Enable “Query Apache server status to determine the sender of email sent from processes running as nobody” in the “[output,url,_1,Exim Configuration Manager,_2,_3]” area\'s “Basic Editor”',
                    $self->base_path('scripts2/displayeximconfforedit'),
                    'target',
                    '_blank'
                ),
            }
        );

    }

    return 1;
}

sub _csf_has_option {
    my ( $option, $value ) = @_;
    if ( -e '/etc/csf/csf.conf' ) {
        my $csf_conf = Cpanel::LoadFile::loadfile('/etc/csf/csf.conf');
        return 1 if $csf_conf =~ m/\n[ \t]*\Q$option\E[ \t]*=[ \t]*['"]\Q$value\E/s;
    }
    return 0;
}

1;
