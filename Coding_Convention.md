## Coding Style

### PR

You'd make the life of the maintainers easier if you submit only _one_ patch with _one_ functional change per PR.

### General
  * Portability is important: Don't use highly system depended binaries (`rpm`, `ip/ifconfig`, ..) as it is not portable. Or it would require lots of efforts (like C's #ifdefs) to be portable plus the code gets ugly.
  * Don't use additional binaries.
  * If you really, really need to use an additional binary make sure it's available on the system before calling it. (Example: see `timeout`.)
  * Keep in mind that binaries might come in different flavors. Especially with ``sed`` you need to be careful as GNU sed is only 80% compatible with BSD sed (`sed -i`,` \n`, `\t`, etc.).
    * Avoid checking for the operating system when using a feature of a binary or an OS. E.g. FreeBSD or MacOSX may or may not have GNU binaries installed, so it's better to check a capability of the binary instead. See how `HAS_*` variables are set.


### Documentation

Some people really read that ! New features would need to be documented in the appropriate section in `help()` and in `~/doc/testssl.1.md`.

### Coding

#### Shell / bash

Bash is actually quite powerful -- not only with respect to sockets. It's not as mighty as perl or python, but there are a lot of neat features. Here's how you make use of them. Besides those short hints here there's a wealth of information of there. One good resource is the [bash hackers wiki](https://wiki.bash-hackers.org/start).

* Don't use backticks anymore, use `$(..)` instead
* Use double square `[[]]` brackets (_conditional expressions)_ instead of single square `[]` brackets
* In double square brackets avoid quoting at the right hand side if not necessary, see [bash hackers wiki](https://wiki.bash-hackers.org/syntax/ccmd/conditional_expression). For regex matching (`=~`) you shouldn't quote at all.
* The [BashPitfalls](http://mywiki.wooledge.org/BashPitfalls) is a good read!
* Whenever possible try to avoid `tr` `sed` `awk` and use bash internal functions instead, see e.g. [bash shell parameter substitution](http://www.cyberciti.biz/tips/bash-shell-parameter-substitution-2.html). It slower as it forks, fopens and pipes back the result.
* `read` often can replace `awk`: `IFS=, read -ra a b c <<< "$line_with_comma"`
* Bash can also deal perfectly with regular expressions, see e.g. [here](https://www.networkworld.com/article/2693361/unix-tip-using-bash-s-regular-expressions.html) and [here](https://unix.stackexchange.com/questions/421460/bash-regex-and-https-regex101-com). You can as well have a look @ `is_ipv4addr()` or `is_ipv6addr()`.
* If you still need to use any of `tr`, `sed` and `awk`: try to avoid a mix of several external binaries e.g. if you can achieve the same with e.g. `awk`.
* Be careful with very advanced bash features. Mac OS X is still using bash version 3 ([differences](http://tldp.org/LDP/abs/html/bashver4.html), see also [bash hackers wiki](https://wiki.bash-hackers.org/scripting/bashchanges)).
* Always use a return value for a function/method. 0 means all is fine.
* Make use of [shellcheck](https://github.com/koalaman/shellcheck) if possible


#### Shell / testssl.sh specific
* Make use the short functions / methods (code starts from `###### START helper function definitions`) like
    * `count_words()` / `count_lines()` / `count_ciphers()`
    * `strip_lf()` / `strip_spaces()`
    * `toupper()` / `tolower()`
    * `newline_to_spaces()`
    * `is_number()` / `is_ipv4addr()`
    * .. and much more
* Security:
    * Watch out for any input especially (but not only) supplied from the server. Input should never be trusted.
    * Unless you're really sure where the values come from, variables need to be put in quotes.
    * You can use `safe_echo()` when processing input which does some input validation.
    *  Use ``out()`` or similar output functions when writing something back to the user.
* Use `$OPENSSL` instead of `openssl`. The latter is highly system depended and also $OPENSSL is a binary which capabilities are checked internally before using it, independent whether the supplied one is being used or another one.

#### Variables
* Use "speaking variables" but don't overdo it with the length
* No camelCase please. We distinguish between lowercase and uppercase only
  * Global variables
    * use them only when really necessary
    * in CAPS
    * initialize them
    * use ``readonly`` and use typing (variable types) if possible
* Local variables
    * are lower case
    * declare them before usage (`local`)
    * initialize them

### Misc

* If you're implementing a new feature a cmd line switch, there has to be also a global ENV variable which can be used without the switch (see e.g. `SNEAKY`, `ASSUME_HTTP` or `ADDTL_CA_FILES`)
* Test before doing a PR! Best if you check with two bad and two good examples which should then work as expected. Maybe compare results e.g. with SSLlabs.
* Unit tests are done automatically done with Perl using Travis. The trigger is `~/.travis.yml`. The general documentation for [Test::More](https://perldoc.perl.org/Test/More.html) is a good start. You are encouraged to write own checks. You can use e.g. `t/20_baseline_ipv4_http.t` as an example.
* If it's an OpenSSL feature you want to use and it could be not available for older OpenSSL versions testssl.sh needs to find out whether OpenSSL has that feature. Best do this with OpenSSL itself and not by checking the version as some vendors do backports. See the examples for `HAS_SSL2` or proxy option check of OpenSSL in `check_proxy()`.
* If a feature of OpenSSL is not available you need to tell this the user by using `pr_warning*()`. Or accordingly with `fatal()` if a continuation of the program doesn't make sense anymore.

