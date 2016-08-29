# How to Contribute

Please contribute using [GitHub Flow](https://guides.github.com/introduction/flow/). Create a branch, add commits, and [open a pull request](https://github.com/cpanelinc/addon_securityadvisor/compare/).

# Contributing Developer Notes

## Assessor Modules 

The Security Advisor encapsulates all of its checks inside of the Perl modules that are located in the [Assessors directory](pkg/Cpanel/Security/Advisor/Assessors).

Each module is a subclass of [Cpanel::Security::Advisor::Assessors](pkg/Cpanel/Security/Advisor/Assessors.pm), as such each module has access to the methods that can add to the notifications.

### Adding New Checks

Please evaluate the list of [Assessors](pkg/Cpanel/Security/Advisor/Assessors) to see if the check you wish to add fits in an existing module.

For existing modules, it is usually preferable to your new check as an isolated subroutine that can be called from the `generate_advice` subroutine. This is the "main" subroutine that is called to drive all the checks. 

If you must create a new module, please study the structure of existing modules. Be prepared to justify why a new module is required and why an existing module is no place for the new check.

## Advice on Advice

### All Advisory Messages Require Unique Static Keys

There are four types of advice defined in `pkg/Cpanel/Security/Advisor/Assessors.pm`, they are:

* `$Cpanel::Security::Advisor::Assessors::ADVISE_GOOD`
* `$Cpanel::Security::Advisor::Assessors::ADVISE_INFO`
* `$Cpanel::Security::Advisor::Assessors::ADVISE_WARN`
* `$Cpanel::Security::Advisor::Assessors::ADVISE_BAD`

They are pretty self explanatory, but it is preferred that any message type of `ADVISE_WARN` or `ADVISE_BAD` also include a `suggestion` for further explanation of the message and what actions may be taken.

Example,

```perl
 $security_advisor_obj->add_advice(
     {
	'key'        => 'EntropyChat_is_running', #<-- required, globally unique static message key
	'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
	'text'       => ['Entropy Chat is running.'],
	'suggestion' => [
	    'Turn off Entropy Chat in the “[output,url,_1,Service Manager,_2,_3]” page.',
	    $self->base_path('scripts/srvmng'),
	    'target',
	    '_blank'
	],
     }
 );
```

### All Advisory Messages Require Unique Static Keys

The general method available to add an Advisory Message is called add_advice. You must specify the advice text and a globally unique static key that is shared by no other messages.

Pull requests that contain new messages without this globally unique static key will be rejected.

The convention being used for determining the static key is as follows. The key must begin with name of the assessor. For example, all keys in `Cpanel::Security::Advisor::Assessors::SSH` begin with *SSH*. What follows is a terse, but meaningful phrase using underscores rather than spaces.

Here are some additional examples of helpful keys that are currently in use:

* `Apache_vhosts_not_segmented`
* `Brute_protection_enabled`
* `Kernel_kernelcare_update_available`

Once a pull request is merged into master, the static keys should never change. The keys are used to track message history, and changing them will result in the same issue that they are meant to solve; i.e., duplicate notifications for previously reported alerts.
