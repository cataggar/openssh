const std = @import("std");

// ---------------------------------------------------------------------------
// A from-scratch Zig build for OpenSSH: every .c file is compiled directly
// through Zig's build graph (addExecutable/addCSourceFiles) -- there is no
// autoreconf, automake, autoconf or `make` involved anymore.
//
// The trade-off: autoconf's several hundred feature-detection checks are
// gone. In their place this repository ships a *frozen*, checked-in
// `config.h` (plus a handful of small header shims under
// `openbsd-compat/include/`) that was captured once via the project's
// normal `./configure` on x86_64 Linux/glibc, with OpenSSL, zlib and PAM
// development headers installed. That means this build.zig only targets
// that same platform shape (glibc/Linux, OpenSSL 3.x, zlib, PAM). Porting
// to another OS/libc requires regenerating config.h by hand (or via the
// autotools flow on the zig16-automake branch) and adjusting the HAVE_*
// defines to match.
//
// `zig build test` builds and runs regress/unittests/* (ported from
// Makefile.in's UNITTESTS_TEST_*_OBJS/`make unit`, see the `unit_tests`
// array below). All suites pass except test_sshkey, which fails at test
// #15 ("equal KEY_RSA/demoted KEY_RSA") -- a pre-existing bug unrelated to
// zig cc or this build.zig (it reproduces identically with a plain gcc +
// autotools build).
// ---------------------------------------------------------------------------

// Flags shared by every compiled .c file, taken verbatim from a real
// `./configure && make CC="zig cc"` build's CFLAGS/CPPFLAGS.
const common_flags = [_][]const u8{
    "-g",
    "-O2",
    "-pipe",
    "-Wunknown-warning-option",
    "-Wno-error=format-truncation",
    "-Qunused-arguments",
    "-Wall",
    "-Wextra",
    "-Wpointer-arith",
    "-Wuninitialized",
    "-Wsign-compare",
    "-Wformat-security",
    "-Wsizeof-pointer-memaccess",
    "-Wno-pointer-sign",
    "-Wno-unused-parameter",
    "-Wno-unused-result",
    "-Wmisleading-indentation",
    "-Wbitwise-instead-of-logical",
    "-fno-strict-aliasing",
    "-D_FORTIFY_SOURCE=2",
    "-ftrapv",
    "-fzero-call-used-regs=used",
    "-ftrivial-auto-var-init=zero",
    "-mretpoline",
    "-fno-builtin-memset",
    "-fstack-protector-strong",
    "-D_XOPEN_SOURCE=600",
    "-D_BSD_SOURCE",
    "-D_DEFAULT_SOURCE",
    "-D_GNU_SOURCE",
    "-DOPENSSL_API_COMPAT=0x10100000L",
    "-DHAVE_CONFIG_H",
};

// libssh.a, libopenbsd-compat.a and the top-level programs are built -fPIE
// (matches Makefile.in's plain $(CFLAGS)); openbsd-compat is built -fPIC
// (matches $(CFLAGS_NOPIE) $(PICFLAG), since historically it could end up
// in a shared object too).
const pie_flags = common_flags ++ [_][]const u8{"-fPIE"};
const pic_flags = common_flags ++ [_][]const u8{"-fPIC"};

const libssh_sources = [_][]const u8{
    // LIBOPENSSH_OBJS (minus ssh_api.c, see libssh_api_sources below)
    "ssherr.c",
    "sshbuf.c",              "sshkey.c",
    "sshbuf-getput-basic.c", "sshbuf-misc.c",
    "sshbuf-getput-crypto.c", "krl.c",
    "bitmap.c",
    // rest of LIBSSH_OBJS
    "authfd.c",              "authfile.c",
    "canohost.c",            "channels.c",
    "cipher.c",              "cipher-aes.c",
    "cipher-aesctr.c",
    "compat.c",              "fatal.c",
    "hostfile.c",            "log.c",
    "match.c",               "moduli.c",
    "nchan.c",               "packet.c",
    "readpass.c",            "ttymodes.c",
    "xmalloc.c",             "addr.c",
    "addrmatch.c",           "atomicio.c",
    "dispatch.c",            "mac.c",
    "misc.c",                "utf8.c",
    "monitor_fdpass.c",      "rijndael.c",
    "ssh-ecdsa.c",           "ssh-ecdsa-sk.c",
    "ssh-ed25519-sk.c",      "ssh-rsa.c",
    "dh.c",                  "msg.c",
    "dns.c",                 "entropy.c",
    "gss-genr.c",            "umac.c",
    "umac128.c",             "smult_curve25519_ref.c",
    "poly1305.c",            "chacha.c",
    "cipher-chachapoly.c",   "cipher-chachapoly-libcrypto.c",
    "ssh-ed25519.c",         "digest-openssl.c",
    "digest-libc.c",         "libcrux-mlkem-mldsa.c",
    "ssh-mldsa-eddsa.c",     "hmac.c",
    "ed25519.c",             "ed25519-openssl.c",
    "kex.c",                 "kex-names.c",
    "kexdh.c",               "kexgex.c",
    "kexecdh.c",             "kexc25519.c",
    "kexgexc.c",             "kexgexs.c",
    "kexsntrup761x25519.c",  "kexmlkem768x25519.c",
    "sntrup761.c",           "kexgen.c",
    "platform-pledge.c",
    "platform-tracing.c",    "platform-misc.c",
    "sshbuf-io.c",           "misc-agent.c",
    "ssherr-libcrypto.c",
};

// cleanup_exit() default implementation, used by the programs below that
// don't provide their own (compare: clientloop.c, scp.c,
// sftp-server-main.c, ssh-agent.c, ssh-pkcs11-helper.c, sshd.c,
// sshd-session.c, sshd-auth.c all define their own). Kept out of
// libssh_sources itself since linking cleanup.c's definition *and* one of
// those programs' own definitions into the same binary would conflict.
const cleanup_sources = [_][]const u8{"cleanup.c"};

// Default (non-crypto, "server-side") sftp_realpath() implementation, used
// directly by sshd-session/sshd-auth/sftp-server (via sftp-server.c). The
// interactive sftp(1) client instead gets its own client-side
// sftp_realpath() from sftp-client.c -- the two are incompatible, same-named
// functions, so (like cleanup.c above) this is kept out of libssh_sources.
const sftp_realpath_sources = [_][]const u8{"sftp-realpath.c"};

// ssh_api.c provides the embeddable "libssh" API, including
// mm_choose_dh()/mm_sshkey_sign() stubs used by kexgexs.c when *not* running
// under the privsep monitor. sshd-session/sshd-auth provide their own real
// implementations of those two in monitor_wrap.c, so they link libssh
// without this file (see the `libssh` field on Program below).
const libssh_api_sources = [_][]const u8{"ssh_api.c"};

const openbsd_compat_sources = [_][]const u8{
    // COMPAT
    "openbsd-compat/bsd-asprintf.c",        "openbsd-compat/bsd-closefrom.c",
    "openbsd-compat/bsd-cygwin_util.c",     "openbsd-compat/bsd-err.c",
    "openbsd-compat/bsd-flock.c",           "openbsd-compat/bsd-getentropy.c",
    "openbsd-compat/bsd-getline.c",         "openbsd-compat/bsd-getpagesize.c",
    "openbsd-compat/bsd-getpeereid.c",      "openbsd-compat/bsd-malloc.c",
    "openbsd-compat/bsd-misc.c",            "openbsd-compat/bsd-nextstep.c",
    "openbsd-compat/bsd-openpty.c",         "openbsd-compat/bsd-poll.c",
    "openbsd-compat/bsd-pselect.c",         "openbsd-compat/bsd-setres_id.c",
    "openbsd-compat/bsd-signal.c",          "openbsd-compat/bsd-snprintf.c",
    "openbsd-compat/bsd-statvfs.c",         "openbsd-compat/bsd-timegm.c",
    "openbsd-compat/bsd-waitpid.c",         "openbsd-compat/fake-rfc2553.c",
    "openbsd-compat/getrrsetbyname-ldns.c", "openbsd-compat/kludge-fd_set.c",
    "openbsd-compat/openssl-compat.c",      "openbsd-compat/libressl-api-compat.c",
    "openbsd-compat/xcrypt.c",
    // OPENBSD
    "openbsd-compat/arc4random.c",          "openbsd-compat/arc4random_uniform.c",
    "openbsd-compat/base64.c",              "openbsd-compat/basename.c",
    "openbsd-compat/bcrypt_pbkdf.c",        "openbsd-compat/bindresvport.c",
    "openbsd-compat/blowfish.c",            "openbsd-compat/daemon.c",
    "openbsd-compat/dirname.c",             "openbsd-compat/explicit_bzero.c",
    "openbsd-compat/fmt_scaled.c",          "openbsd-compat/freezero.c",
    "openbsd-compat/fnmatch.c",             "openbsd-compat/getcwd.c",
    "openbsd-compat/getgrouplist.c",        "openbsd-compat/getopt_long.c",
    "openbsd-compat/getrrsetbyname.c",      "openbsd-compat/glob.c",
    "openbsd-compat/inet_aton.c",           "openbsd-compat/inet_ntoa.c",
    "openbsd-compat/inet_ntop.c",           "openbsd-compat/md5.c",
    "openbsd-compat/memmem.c",              "openbsd-compat/mktemp.c",
    "openbsd-compat/pwcache.c",             "openbsd-compat/readpassphrase.c",
    "openbsd-compat/reallocarray.c",        "openbsd-compat/recallocarray.c",
    "openbsd-compat/rresvport.c",           "openbsd-compat/setenv.c",
    "openbsd-compat/setproctitle.c",        "openbsd-compat/sha1.c",
    "openbsd-compat/sha2.c",                "openbsd-compat/sigact.c",
    "openbsd-compat/strcasestr.c",          "openbsd-compat/strlcat.c",
    "openbsd-compat/strlcpy.c",             "openbsd-compat/strmode.c",
    "openbsd-compat/strndup.c",             "openbsd-compat/strnlen.c",
    "openbsd-compat/strptime.c",            "openbsd-compat/strsep.c",
    "openbsd-compat/strtoll.c",             "openbsd-compat/strtonum.c",
    "openbsd-compat/strtoull.c",            "openbsd-compat/strtoul.c",
    "openbsd-compat/timingsafe_bcmp.c",     "openbsd-compat/vis.c",
    // PORTS
    "openbsd-compat/port-aix.c",            "openbsd-compat/port-irix.c",
    "openbsd-compat/port-linux.c",          "openbsd-compat/port-prngd.c",
    "openbsd-compat/port-solaris.c",        "openbsd-compat/port-net.c",
    "openbsd-compat/port-uw.c",
};

const p11_client_sources = [_][]const u8{"ssh-pkcs11-client.c"};
const sk_client_sources = [_][]const u8{"ssh-sk-client.c"};
const sftp_client_sources = [_][]const u8{
    "sftp-common.c", "sftp-client.c", "sftp-glob.c", "ssherr-nolibcrypto.c",
};

const Program = struct {
    name: []const u8,
    sources: []const []const u8,
    /// Needs -lpam -ldl (sshd, sshd-session, sshd-auth).
    needs_pam: bool = false,
    /// Which libssh variant (if any) to link:
    ///  - .full: the normal libssh.a (client-side tools; provides ssh_api.c's
    ///    non-privsep mm_choose_dh/mm_sshkey_sign stubs used by kexgexs.c).
    ///  - .no_api: libssh built without ssh_api.c, for the privsep-monitor
    ///    server binaries that provide their own real
    ///    mm_choose_dh/mm_sshkey_sign in monitor_wrap.c (linking the .full
    ///    variant here would duplicate those two symbols).
    ///  - .no_crypto_err: libssh built without ssherr-libcrypto.c (and
    ///    without ssh_api.c), for scp/sftp/sftp-server/ssh-sk-helper, which
    ///    provide their own ssh_err() etc. via ssherr-nolibcrypto.c
    ///    directly (linking the .full variant here would duplicate that).
    libssh: enum { full, no_api, no_crypto_err } = .full,
};

const programs = [_]Program{
    .{
        .name = "ssh",
        .sources = &([_][]const u8{
            "ssh.c",         "readconf.c", "clientloop.c", "sshtty.c",
            "sshconnect.c",  "sshconnect2.c", "mux.c",      "ssh-pkcs11.c",
        } ++ sk_client_sources),
    },
    .{
        .name = "sshd",
        .needs_pam = true,
        .sources = &([_][]const u8{
            "sshd.c",          "platform-listen.c", "servconf.c",
            "sshpty.c",        "srclimit.c",        "groupaccess.c",
            "auth2-methods.c", "dns.c",
        } ++ p11_client_sources ++ sk_client_sources),
    },
    .{
        .name = "sshd-session",
        .needs_pam = true,
        .libssh = .no_api,
        .sources = &([_][]const u8{
            "sshd-session.c",    "auth-rhosts.c",    "auth-passwd.c",
            "audit.c",           "audit-bsm.c",      "audit-linux.c",
            "platform.c",        "sshpty.c",         "sshlogin.c",
            "servconf.c",        "serverloop.c",     "auth.c",
            "auth2.c",           "auth2-methods.c",  "auth-options.c",
            "session.c",         "auth2-chall.c",    "groupaccess.c",
            "auth-bsdauth.c",    "auth2-hostbased.c", "auth2-kbdint.c",
            "auth2-none.c",      "auth2-passwd.c",   "auth2-pubkey.c",
            "auth2-pubkeyfile.c", "monitor.c",       "monitor_wrap.c",
            "auth-krb5.c",       "auth2-gss.c",      "gss-serv.c",
            "gss-serv-krb5.c",   "loginrec.c",       "auth-pam.c",
            "auth-shadow.c",     "auth-sia.c",       "sftp-server.c",
            "sftp-common.c",     "uidswap.c",        "platform-listen.c",
        } ++ p11_client_sources ++ sk_client_sources ++ sftp_realpath_sources),
    },
    .{
        .name = "sshd-auth",
        .needs_pam = true,
        .libssh = .no_api,
        .sources = &([_][]const u8{
            "sshd-auth.c",       "auth2-methods.c",  "auth-rhosts.c",
            "auth-passwd.c",     "sshpty.c",         "sshlogin.c",
            "servconf.c",        "serverloop.c",     "auth.c",
            "auth2.c",           "auth-options.c",   "session.c",
            "auth2-chall.c",     "groupaccess.c",    "auth-bsdauth.c",
            "auth2-hostbased.c", "auth2-kbdint.c",   "auth2-none.c",
            "auth2-passwd.c",    "auth2-pubkey.c",   "auth2-pubkeyfile.c",
            "auth2-gss.c",       "gss-serv.c",       "gss-serv-krb5.c",
            "monitor_wrap.c",    "auth-krb5.c",      "audit.c",
            "audit-bsm.c",       "audit-linux.c",    "platform.c",
            "loginrec.c",        "auth-pam.c",       "auth-shadow.c",
            "auth-sia.c",        "sandbox-null.c",   "sandbox-rlimit.c",
            "sandbox-darwin.c",  "sandbox-seccomp-filter.c", "sandbox-capsicum.c",
            "sandbox-solaris.c", "sftp-server.c",    "sftp-common.c",
            "uidswap.c",
        } ++ p11_client_sources ++ sk_client_sources ++ sftp_realpath_sources),
    },
    .{
        .name = "ssh-add",
        .sources = &([_][]const u8{"ssh-add.c"} ++ p11_client_sources ++ sk_client_sources ++ cleanup_sources),
    },
    .{
        .name = "ssh-agent",
        .sources = &([_][]const u8{"ssh-agent.c"} ++ p11_client_sources ++ sk_client_sources),
    },
    .{
        .name = "ssh-keygen",
        .sources = &([_][]const u8{ "ssh-keygen.c", "sshsig.c", "ssh-pkcs11.c" } ++ sk_client_sources ++ cleanup_sources),
    },
    .{
        .name = "ssh-keysign",
        .sources = &([_][]const u8{ "ssh-keysign.c", "readconf.c", "uidswap.c" } ++ p11_client_sources ++ sk_client_sources ++ cleanup_sources),
    },
    .{
        .name = "ssh-pkcs11-helper",
        .sources = &([_][]const u8{ "ssh-pkcs11-helper.c", "ssh-pkcs11.c" } ++ sk_client_sources),
    },
    .{
        .name = "ssh-keyscan",
        .sources = &([_][]const u8{"ssh-keyscan.c"} ++ p11_client_sources ++ sk_client_sources ++ cleanup_sources),
    },
    .{
        .name = "ssh-sk-helper",
        .libssh = .no_crypto_err,
        .sources = &([_][]const u8{ "ssh-sk-helper.c", "ssh-sk.c", "sk-usbhid.c", "ssherr-nolibcrypto.c" } ++ cleanup_sources),
    },
    .{
        .name = "scp",
        .libssh = .no_crypto_err,
        .sources = &([_][]const u8{ "scp.c", "progressmeter.c" } ++ sftp_client_sources),
    },
    .{
        .name = "sftp",
        .libssh = .no_crypto_err,
        .sources = &([_][]const u8{ "sftp.c", "sftp-usergroup.c", "progressmeter.c" } ++ sftp_client_sources ++ cleanup_sources),
    },
    .{
        .name = "sftp-server",
        .libssh = .no_crypto_err,
        .sources = &([_][]const u8{ "sftp-common.c", "sftp-server.c", "sftp-server-main.c", "ssherr-nolibcrypto.c" } ++ sftp_realpath_sources),
    },
};

// regress/unittests/*: self-contained unit tests (see also
// regress/unittests/Makefile.inc, which drives these under the real BSD
// make; and Makefile.in's UNITTESTS_TEST_*_OBJS, which drives them under
// the portable autotools/GNU-make build -- this list is derived from the
// latter). Every test links against libtest_helper + the full libssh +
// libopenbsd_compat, exactly like the "ssh" client program.
const UnitTest = struct {
    name: []const u8,
    dir: []const u8,
    /// Sources under `dir`, without the directory prefix.
    sources: []const []const u8,
    /// Extra non-test sources needed directly (not provided by libssh),
    /// e.g. auth-options.c for authopt, servconf.c for servconf.
    extra_sources: []const []const u8 = &.{},
    /// Needs ssh-pkcs11-client.c/ssh-sk-client.c directly.
    needs_p11sk: bool = false,
    /// Run with `-d <dir>/testdata`.
    needs_testdata: bool = false,
};

const unit_tests = [_]UnitTest{
    .{
        .name = "test_sshbuf",
        .dir = "regress/unittests/sshbuf",
        .sources = &[_][]const u8{
            "tests.c", "test_sshbuf.c", "test_sshbuf_getput_basic.c",
            "test_sshbuf_getput_crypto.c", "test_sshbuf_misc.c",
            "test_sshbuf_fuzz.c", "test_sshbuf_getput_fuzz.c", "test_sshbuf_fixed.c",
        },
    },
    .{
        .name = "test_sshkey",
        .dir = "regress/unittests/sshkey",
        .sources = &[_][]const u8{ "test_fuzz.c", "tests.c", "common.c", "test_file.c", "test_sshkey.c" },
        .needs_p11sk = true,
        .needs_testdata = true,
    },
    .{
        .name = "test_sshsig",
        .dir = "regress/unittests/sshsig",
        .sources = &[_][]const u8{"tests.c"},
        .extra_sources = &[_][]const u8{"sshsig.c"},
        .needs_p11sk = true,
        .needs_testdata = true,
    },
    .{
        .name = "test_authopt",
        .dir = "regress/unittests/authopt",
        .sources = &[_][]const u8{"tests.c"},
        .extra_sources = &[_][]const u8{"auth-options.c"},
        .needs_p11sk = true,
        .needs_testdata = true,
    },
    .{
        .name = "test_bitmap",
        .dir = "regress/unittests/bitmap",
        .sources = &[_][]const u8{"tests.c"},
    },
    .{
        .name = "test_conversion",
        .dir = "regress/unittests/conversion",
        .sources = &[_][]const u8{"tests.c"},
    },
    .{
        .name = "test_kex",
        .dir = "regress/unittests/kex",
        .sources = &[_][]const u8{ "tests.c", "test_kex.c", "test_proposal.c" },
        .needs_p11sk = true,
    },
    .{
        .name = "test_hostkeys",
        .dir = "regress/unittests/hostkeys",
        .sources = &[_][]const u8{ "tests.c", "test_iterate.c" },
        .needs_p11sk = true,
        .needs_testdata = true,
    },
    .{
        .name = "test_match",
        .dir = "regress/unittests/match",
        .sources = &[_][]const u8{"tests.c"},
    },
    .{
        .name = "test_misc",
        .dir = "regress/unittests/misc",
        .sources = &[_][]const u8{
            "tests.c",          "test_parse.c",     "test_expand.c",
            "test_convtime.c",  "test_argv.c",       "test_strdelim.c",
            "test_hpdelim.c",   "test_ptimeout.c",   "test_xextendf.c",
            "test_misc.c",
        },
    },
    .{
        .name = "test_servconf",
        .dir = "regress/unittests/servconf",
        .sources = &[_][]const u8{"tests.c"},
        .extra_sources = &[_][]const u8{ "servconf.c", "groupaccess.c" },
        .needs_p11sk = true,
    },
    .{
        .name = "test_crypto",
        .dir = "regress/unittests/crypto",
        .sources = &[_][]const u8{
            "test_ed25519.c", "test_mldsa.c", "test_mldsa_eddsa.c",
            "test_mlkem.c",   "tests.c",
        },
        .needs_p11sk = true,
        .needs_testdata = true,
    },
    .{
        .name = "test_utf8",
        .dir = "regress/unittests/utf8",
        .sources = &[_][]const u8{"tests.c"},
    },
};

pub fn build(b: *std.Build) void {
    // config.h/openbsd-compat/include are frozen for native glibc/Linux;
    // cross-compiling is not expected to work, but the option is left in
    // place since it's otherwise idiomatic zig build boilerplate.
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const prefix = b.option([]const u8, "install-prefix", "Baked-in default install prefix (default: /usr/local)") orelse "/usr/local";
    const sysconfdir = b.option([]const u8, "sysconfdir", "Baked-in default config directory") orelse b.fmt("{s}/etc", .{prefix});
    const piddir = b.option([]const u8, "piddir", "Baked-in default pid file directory") orelse "/var/run";
    const privsep_path = b.option([]const u8, "privsep-path", "Baked-in privilege separation chroot directory") orelse "/var/empty";

    const path_flags = [_][]const u8{
        b.fmt("-DSSHDIR=\"{s}\"", .{sysconfdir}),
        b.fmt("-D_PATH_SSH_PROGRAM=\"{s}/bin/ssh\"", .{prefix}),
        b.fmt("-D_PATH_SSH_ASKPASS_DEFAULT=\"{s}/libexec/ssh-askpass\"", .{prefix}),
        b.fmt("-D_PATH_SFTP_SERVER=\"{s}/libexec/sftp-server\"", .{prefix}),
        b.fmt("-D_PATH_SSH_KEY_SIGN=\"{s}/libexec/ssh-keysign\"", .{prefix}),
        b.fmt("-D_PATH_SSHD_SESSION=\"{s}/libexec/sshd-session\"", .{prefix}),
        b.fmt("-D_PATH_SSHD_AUTH=\"{s}/libexec/sshd-auth\"", .{prefix}),
        b.fmt("-D_PATH_SSH_PKCS11_HELPER=\"{s}/libexec/ssh-pkcs11-helper\"", .{prefix}),
        b.fmt("-D_PATH_SSH_SK_HELPER=\"{s}/libexec/ssh-sk-helper\"", .{prefix}),
        b.fmt("-D_PATH_SSH_PIDDIR=\"{s}\"", .{piddir}),
        b.fmt("-D_PATH_PRIVSEP_CHROOT_DIR=\"{s}\"", .{privsep_path}),
    };
    const top_flags = pie_flags ++ path_flags;

    // libssh_sources minus one file, for building the alternate libssh
    // variants below (see the `libssh` field comment on Program).
    const arena = b.allocator;
    const excluding = struct {
        fn call(alloc: std.mem.Allocator, list: []const []const u8, exclude: []const u8) []const []const u8 {
            var out: std.ArrayListUnmanaged([]const u8) = .empty;
            for (list) |item| {
                if (!std.mem.eql(u8, item, exclude)) out.append(alloc, item) catch @panic("OOM");
            }
            return out.toOwnedSlice(alloc) catch @panic("OOM");
        }
    }.call;
    const libssh_sources_no_crypto_err = excluding(arena, &libssh_sources, "ssherr-libcrypto.c");

    // libopenbsd-compat.a: OpenBSD/BSD portability shims. Always compiled
    // in full; unneeded functions become no-ops via config.h HAVE_* guards.
    const compat_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    compat_mod.addIncludePath(b.path("."));
    compat_mod.addIncludePath(b.path("openbsd-compat"));
    compat_mod.addIncludePath(b.path("openbsd-compat/include"));
    compat_mod.addCSourceFiles(.{ .files = &openbsd_compat_sources, .flags = &pic_flags });
    const libopenbsd_compat = b.addLibrary(.{
        .name = "openbsd-compat",
        .linkage = .static,
        .root_module = compat_mod,
    });

    // libssh.a: the shared protocol/crypto/utility code linked into every
    // client-side program below. Includes ssh_api.c (see comment above).
    const ssh_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ssh_mod.addIncludePath(b.path("."));
    ssh_mod.addIncludePath(b.path("openbsd-compat/include"));
    ssh_mod.addCSourceFiles(.{ .files = &libssh_sources, .flags = &top_flags });
    ssh_mod.addCSourceFiles(.{ .files = &libssh_api_sources, .flags = &top_flags });
    const libssh = b.addLibrary(.{
        .name = "ssh",
        .linkage = .static,
        .root_module = ssh_mod,
    });

    // Same as libssh, but without ssh_api.c, for the privsep-monitor server
    // binaries (sshd-session, sshd-auth) -- see the `libssh` field comment
    // on Program above.
    const ssh_no_api_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ssh_no_api_mod.addIncludePath(b.path("."));
    ssh_no_api_mod.addIncludePath(b.path("openbsd-compat/include"));
    ssh_no_api_mod.addCSourceFiles(.{ .files = &libssh_sources, .flags = &top_flags });
    const libssh_no_api = b.addLibrary(.{
        .name = "ssh-no-api",
        .linkage = .static,
        .root_module = ssh_no_api_mod,
    });

    // Same as libssh, but without ssherr-libcrypto.c or ssh_api.c, for the
    // non-crypto sftp/scp/ssh-sk-helper tools, which provide their own
    // ssh_err() etc. via ssherr-nolibcrypto.c directly (see the `libssh`
    // field comment on Program above).
    const ssh_no_crypto_err_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ssh_no_crypto_err_mod.addIncludePath(b.path("."));
    ssh_no_crypto_err_mod.addIncludePath(b.path("openbsd-compat/include"));
    ssh_no_crypto_err_mod.addCSourceFiles(.{ .files = libssh_sources_no_crypto_err, .flags = &top_flags });
    const libssh_no_crypto_err = b.addLibrary(.{
        .name = "ssh-no-crypto-err",
        .linkage = .static,
        .root_module = ssh_no_crypto_err_mod,
    });

    for (programs) |prog| {
        const mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        mod.addIncludePath(b.path("."));
        mod.addIncludePath(b.path("openbsd-compat/include"));
        mod.addCSourceFiles(.{ .files = prog.sources, .flags = &top_flags });
        switch (prog.libssh) {
            .full => mod.linkLibrary(libssh),
            .no_api => mod.linkLibrary(libssh_no_api),
            .no_crypto_err => mod.linkLibrary(libssh_no_crypto_err),
        }
        mod.linkLibrary(libopenbsd_compat);
        mod.linkSystemLibrary("crypto", .{});
        mod.linkSystemLibrary("z", .{});
        if (prog.needs_pam) {
            mod.linkSystemLibrary("pam", .{});
            mod.linkSystemLibrary("dl", .{});
        }

        const exe = b.addExecutable(.{
            .name = prog.name,
            .root_module = mod,
        });
        exe.pie = true;
        b.installArtifact(exe);
    }

    // regress/unittests/test_helper: small assertion/benchmark harness
    // shared by every unit test below.
    const test_helper_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_helper_mod.addIncludePath(b.path("."));
    test_helper_mod.addIncludePath(b.path("openbsd-compat/include"));
    test_helper_mod.addCSourceFiles(.{
        .files = &[_][]const u8{
            "regress/unittests/test_helper/test_helper.c",
            "regress/unittests/test_helper/fuzz.c",
        },
        .flags = &top_flags,
    });
    const libtest_helper = b.addLibrary(.{
        .name = "test_helper",
        .linkage = .static,
        .root_module = test_helper_mod,
    });

    const test_step = b.step("test", "Build and run the regress/unittests/* unit test suite");
    for (unit_tests) |ut| {
        const mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        mod.addIncludePath(b.path("."));
        mod.addIncludePath(b.path("openbsd-compat/include"));

        const dir_sources = b.allocator.alloc([]const u8, ut.sources.len) catch @panic("OOM");
        for (ut.sources, 0..) |src, i| dir_sources[i] = b.pathJoin(&.{ ut.dir, src });
        mod.addCSourceFiles(.{ .files = dir_sources, .flags = &top_flags });

        if (ut.extra_sources.len > 0)
            mod.addCSourceFiles(.{ .files = ut.extra_sources, .flags = &top_flags });
        if (ut.needs_p11sk) {
            mod.addCSourceFiles(.{ .files = &p11_client_sources, .flags = &top_flags });
            mod.addCSourceFiles(.{ .files = &sk_client_sources, .flags = &top_flags });
        }
        mod.addCSourceFiles(.{ .files = &cleanup_sources, .flags = &top_flags });

        mod.linkLibrary(libssh);
        mod.linkLibrary(libopenbsd_compat);
        mod.linkLibrary(libtest_helper);
        mod.linkSystemLibrary("crypto", .{});
        mod.linkSystemLibrary("z", .{});

        const exe = b.addExecutable(.{
            .name = ut.name,
            .root_module = mod,
        });
        exe.pie = true;

        const run = b.addRunArtifact(exe);
        if (ut.needs_testdata)
            run.addArgs(&.{ "-d", b.pathJoin(&.{ ut.dir, "testdata" }) });
        test_step.dependOn(&run.step);
    }

    // Using this repository from another Zig project's build.zig:
    //
    //   const openssh_dep = b.dependency("openssh_portable", .{
    //       .target = target,
    //       .optimize = optimize,
    //   });
    //   const ssh_exe = openssh_dep.artifact("ssh");
    //   const sshd_exe = openssh_dep.artifact("sshd-session");
    //   b.installArtifact(ssh_exe);
    //
    // Every program in `programs` above is a real `*Step.Compile` installed
    // via `b.installArtifact`, so `dep.artifact("<name>")` works for any of
    // them (ssh, sshd, sshd-session, sshd-auth, scp, sftp, sftp-server,
    // ssh-add, ssh-agent, ssh-keygen, ssh-keyscan, ssh-keysign,
    // ssh-pkcs11-helper, ssh-sk-helper).
}

