const std = @import("std");

// This build.zig is a thin wrapper around OpenSSH's existing autotools build
// (autoreconf / configure / make). It does not reimplement the compilation
// of OpenSSH's several hundred C files in Zig's build graph; instead it
// drives the existing, well-tested autotools flow using `zig cc` as the C
// compiler. This lets `zig build` work standalone in this repository, and
// lets another Zig project depend on this one (see the notes at the bottom
// of this file for how a consumer should do that).
pub fn build(b: *std.Build) void {
    const with_pam = b.option(bool, "pam", "Enable PAM support (default: true)") orelse true;
    const with_kerberos = b.option(bool, "kerberos", "Enable Kerberos5/GSSAPI support (default: false)") orelse false;
    const with_selinux = b.option(bool, "selinux", "Enable SELinux support (default: false)") orelse false;
    const reconfigure = b.option(bool, "reconfigure", "Force re-running autoreconf and configure (default: false)") orelse false;
    const configure_args = b.option([]const []const u8, "configure-arg", "Extra argument to forward to ./configure (may be repeated)") orelse &.{};
    const jobs = b.option(u32, "jobs", "make -j parallelism (default: number of CPUs)");

    // Everything below operates in-tree, i.e. directly inside this
    // package's source root (`b.path(".")`), exactly like a manual
    // `./configure && make` checkout build. This keeps the wrapper simple
    // and matches how the project is built today.
    const root = b.path(".");

    var prev_step: ?*std.Build.Step = null;
    const io = b.graph.io;

    const have_configure = if (b.build_root.handle.access(io, "configure", .{})) |_| true else |_| false;
    if (reconfigure or !have_configure) {
        const autoreconf = b.addSystemCommand(&.{ "autoreconf", "-i" });
        autoreconf.setCwd(root);
        prev_step = &autoreconf.step;
    }

    const have_makefile = if (b.build_root.handle.access(io, "Makefile", .{})) |_| true else |_| false;
    if (reconfigure or !have_makefile) {
        const configure = b.addSystemCommand(&.{"./configure"});
        configure.setCwd(root);
        configure.setEnvironmentVariable("CC", "zig cc");
        if (with_pam) configure.addArg("--with-pam");
        if (with_kerberos) configure.addArg("--with-kerberos5");
        if (with_selinux) configure.addArg("--with-selinux");
        configure.addArgs(configure_args);
        if (prev_step) |s| configure.step.dependOn(s);
        prev_step = &configure.step;
    }

    const make = b.addSystemCommand(&.{"make"});
    make.setCwd(root);
    const jobs_arg = b.fmt("-j{d}", .{jobs orelse @as(u32, @intCast(std.Thread.getCpuCount() catch 1))});
    make.addArg(jobs_arg);
    if (prev_step) |s| make.step.dependOn(s);

    b.getInstallStep().dependOn(&make.step);

    // `zig build test` builds and runs OpenSSH's self-contained unit tests
    // (regress/unittests/*), i.e. `make unit`.
    const unit = b.addSystemCommand(&.{ "make", "unit" });
    unit.setCwd(root);
    unit.step.dependOn(&make.step);
    const test_step = b.step("test", "Run OpenSSH's unit test suite (make unit)");
    test_step.dependOn(&unit.step);

    // `zig build clean` runs `make distclean`, undoing autoreconf/configure
    // as well as the compiled objects/binaries.
    const clean = b.addSystemCommand(&.{ "make", "distclean" });
    clean.setCwd(root);
    const clean_step = b.step("clean", "Remove all configure/build output (make distclean)");
    clean_step.dependOn(&clean.step);

    // Using this repository from another Zig project's build.zig:
    //
    //   const openssh_dep = b.dependency("openssh_portable", .{
    //       .pam = true,
    //   });
    //   // Make sure configure/make has actually run before relying on the
    //   // binaries below:
    //   my_step.dependOn(openssh_dep.builder.getInstallStep());
    //   // Built binaries land in-tree, next to the fetched sources:
    //   const ssh_exe = openssh_dep.path("ssh");
    //   const sshd_exe = openssh_dep.path("sshd");
}
