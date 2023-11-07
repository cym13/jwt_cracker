Description
===========

This JWT cracking tool performs highly-parallel dictionary and bruteforce
attacks. You can specify both at the same time, it will attempt the
dictionary attack first then switch to bruteforce if a solution hasn't yet
been found.

It is written in D for ease of development, natively compiled performance and
tight control over memory usage.

Why not hashcat?
================

You should probably use hashcat.

Why this weird default alphabet for bruteforce?
===============================================

This alphabet was the result of frequency analysis on several large leaked
password databases, sorted from the most frequent character to the least.
The selected alphabet successfully cracks 74% of the passwords studied.
We could aim for higher but we're dealing with exponential growth so
any letter added to the alphabet costs a lot of time. This felt like a nice
balance but your mileage may vary.

Example
=======

On an old Intel Core i7-3520M, using bruteforce with the default alphabet and
a length from 0 to infinity.

.. code:: bash

    $ jwt_cracker eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidG9tbXkifQ.RvkA8i0Cr4FE4QST9bkTz6eq2fBgDv5NKKeMgfPlm7tPKSMmfMu8BNxsPYBbXZJMELg-eNq2mqPTvATn4r_GQw
    Header: {"alg":"HS512","typ":"JWT"}
    Payload: {"name":"tommy"}
    Signature:
    46F900F22D02AF8144E10493F5B913CFA7AAD9F0600EFE4D28A78C81F3E59BBB4F2923267CCBBC04DC6C3D805B5D924C10B83E78DAB69AA3D3BC04E7E2BFC643

    $ time jwt_cracker -B -l - eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidG9tbXkifQ.RvkA8i0Cr4FE4QST9bkTz6eq2fBgDv5NKKeMgfPlm7tPKSMmfMu8BNxsPYBbXZJMELg-eNq2mqPTvATn4r_GQw
    Found: secret
    jwt_cracker -B -l -   1153.32s user 1.07s system 378% cpu 5:04.83 total 5m:5s


Documentation
=============

::

    Optimized JWT HMAC cracker

    Usage: jwt_cracker [options] JWT
           jwt_cracker [options] -H HEADER -P payload -S secret
           jwt_cracker [options] -d DIC JWT
           jwt_cracker [options] (-B|-b ALPH) -l LENGTH JWT

    Arguments:
        JWT     JWT to crack. Without any option, parses the JWT and prints it.
                jwt_cracker supports 3 sets of options for 3 different
                operations: encoding, dictionary attack and bruteforce attack.
                Specifying multiple sets of options at once resolves them in the
                order shown above.

    Options:
        -h, --help                  Print this help and exit
        -v, --version               Print version and exit

        -H, --header HEADER         Header to encode JWT
        -P, --payload PAYLOAD       Payload to encode JWT
        -S, --secret SECRET         Secret to encode JWT

        -d, --dictionary DIC        Perform dictionary attack with file DIC
                                    Use - to read from stdin

        -b, --bruteforce ALPH       Perform bruteforce attack with alphabet
        -B, --default-bruteforce    Perform bruteforce attack with default alphabet
                                    Default: ae1ionrls0t2mc8uhyb93pgk5467vfj
        -l, --length LENGTH         Minimum length for bruteforce attack
                                    If it contains a dash, acts as a min-max range
                                    Eg: 0-7 means 0 to 7 characters long.
                                        3-  means 3 to infinity

Building
========

Use dub. Usage of the LDC compiler is *strongly* recommended for performance.

::

    dub build -b release --compiler=ldc

License
=======

This program is under the GPLv3 License.

You should have received a copy of the GNU General Public License
along with this program. If not, see http://www.gnu.org/licenses/.

Contact
=======

::

    Main developper: Cédric Picard
    Email:           cpicard@purrfect.fr
