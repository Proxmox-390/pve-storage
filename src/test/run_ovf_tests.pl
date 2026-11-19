#!/usr/bin/perl

use strict;
use warnings;
use lib qw(..); # prepend .. to @INC so we use the local version of PVE packages

use FindBin '$Bin';
use PVE::GuestImport::OVF;
use Test::More;
use File::Temp;
use PVE::Tools;

use Data::Dumper;

my $test_manifests = join('/', $Bin, 'ovf_manifests');

print "parsing ovfs\n";

my $win2008 =
    eval { PVE::GuestImport::OVF::parse_ovf("$test_manifests/Win_2008_R2_two-disks.ovf") };
if (my $err = $@) {
    fail('parse win2008');
    warn("error: $err\n");
} else {
    ok('parse win2008');
}
my $win10 = eval { PVE::GuestImport::OVF::parse_ovf("$test_manifests/Win10-Liz.ovf") };
if (my $err = $@) {
    fail('parse win10');
    warn("error: $err\n");
} else {
    ok('parse win10');
}
my $win10noNs =
    eval { PVE::GuestImport::OVF::parse_ovf("$test_manifests/Win10-Liz_no_default_ns.ovf") };
if (my $err = $@) {
    fail("parse win10 no default rasd NS");
    warn("error: $err\n");
} else {
    ok('parse win10 no default rasd NS');
}

my $xee = eval { PVE::GuestImport::OVF::parse_ovf("$test_manifests/XEE.ovf") };
if (my $err = $@) {
    ok("parsing XEE.ovf failed as expected");
} else {
    fail('parsing XEE.ovf should have failed!');
}

print "testing disks\n";

is(
    $win2008->{disks}->[0]->{disk_address},
    'scsi0',
    'multidisk vm has the correct first disk controller',
);
is(
    $win2008->{disks}->[0]->{backing_file},
    "$test_manifests/disk1.vmdk",
    'multidisk vm has the correct first disk backing device',
);
is($win2008->{disks}->[0]->{virtual_size}, 2048, 'multidisk vm has the correct first disk size');

is(
    $win2008->{disks}->[1]->{disk_address},
    'scsi1',
    'multidisk vm has the correct second disk controller',
);
is(
    $win2008->{disks}->[1]->{backing_file},
    "$test_manifests/disk2.vmdk",
    'multidisk vm has the correct second disk backing device',
);
is($win2008->{disks}->[1]->{virtual_size}, 2048, 'multidisk vm has the correct second disk size');

is($win10->{disks}->[0]->{disk_address}, 'scsi0', 'single disk vm has the correct disk controller');
is(
    $win10->{disks}->[0]->{backing_file},
    "$test_manifests/Win10-Liz-disk1.vmdk",
    'single disk vm has the correct disk backing device',
);
is($win10->{disks}->[0]->{virtual_size}, 2048, 'single disk vm has the correct size');

is(
    $win10noNs->{disks}->[0]->{disk_address},
    'scsi0',
    'single disk vm (no default rasd NS) has the correct disk controller',
);
is(
    $win10noNs->{disks}->[0]->{backing_file},
    "$test_manifests/Win10-Liz-disk1.vmdk",
    'single disk vm (no default rasd NS) has the correct disk backing device',
);
is(
    $win10noNs->{disks}->[0]->{virtual_size},
    2048,
    'single disk vm (no default rasd NS) has the correct size',
);

print "testing nics\n";
is($win2008->{net}->{net0}->{model}, 'e1000', 'win2008 has correct nic model');
is($win10->{net}->{net0}->{model}, 'e1000e', 'win10 has correct nic model');
is($win10noNs->{net}->{net0}->{model}, 'e1000e',
    'win10 (no default rasd NS) has correct nic model');

print "\ntesting vm.conf extraction\n";

is($win2008->{qm}->{boot}, 'order=scsi0;scsi1', 'win2008 VM boot is correct');
is($win2008->{qm}->{name}, 'Win2008-R2x64', 'win2008 VM name is correct');
is($win2008->{qm}->{memory}, '2048', 'win2008 VM memory is correct');
is($win2008->{qm}->{cores}, '1', 'win2008 VM cores are correct');
is($win2008->{qm}->{ostype}, 'win7', 'win2008 VM ostype is correcty');

is($win10->{qm}->{boot}, 'order=scsi0', 'win10 VM boot is correct');
is($win10->{qm}->{name}, 'Win10-Liz', 'win10 VM name is correct');
is($win10->{qm}->{memory}, '6144', 'win10 VM memory is correct');
is($win10->{qm}->{cores}, '4', 'win10 VM cores are correct');
# older esxi/ovf standard used 'other' for windows10
is($win10->{qm}->{ostype}, 'other', 'win10 VM ostype is correct');

is($win10noNs->{qm}->{boot}, 'order=scsi0', 'win10 VM (no default rasd NS) boot is correct');
is($win10noNs->{qm}->{name}, 'Win10-Liz', 'win10 VM (no default rasd NS) name is correct');
is($win10noNs->{qm}->{memory}, '6144', 'win10 VM (no default rasd NS) memory is correct');
is($win10noNs->{qm}->{cores}, '4', 'win10 VM (no default rasd NS) cores are correct');
# older esxi/ovf standard used 'other' for windows10
is($win10noNs->{qm}->{ostype}, 'other', 'win10 VM (no default rasd NS) ostype is correct');
is($win10noNs->{qm}->{bios}, 'ovmf', 'win10 VM (no default rasd NS) bios is correct');

print "\ntesting the Proxmox VE configuration section\n";

# OVAs as Proxmox VE exports them (qm export-ova); the disk images are not needed for parsing
my $tmpdir = File::Temp->newdir();
my sub make_ova {
    my ($ovf) = @_;
    my $name = "$tmpdir/$ovf.ova";
    system('tar', '-cf', $name, '-C', $test_manifests, $ovf) == 0 or die "tar failed\n";
    return $name;
}

my $mf_ova = make_ova('mf01-s390x.ovf');
my $mf = PVE::GuestImport::OVF::parse_ovf($mf_ova, 1, 0, 's390x');
is_deeply(
    [map { $_->{disk_address} } $mf->{disks}->@*],
    [qw(ckd0 ckd1 ckd2)],
    's390x: DASDs keep their configuration keys',
);
is_deeply(
    $mf->{disks}->[0]->{options},
    { devno => '0.0.0200' },
    's390x: ckd0 keeps its device number, the cylinders come from the image',
);
is($mf->{disks}->[1]->{relative_path}, 'x-ckd1.vmdk', 's390x: ckd1 image');
is($mf->{disks}->[0]->{virtual_size}, 8339153 * 1024, 's390x: ckd0 size');
is(PVE::GuestImport::OVF::try_parse_capacity_unit('byte'), 1, 'capacity in bytes');
is_deeply(
    $mf->{net},
    {
        net0 => {
            model => 'qeth',
            macaddr => 'BC:24:11:6C:CE:D6',
            bridge => 'vmbr1',
            devno => '0.0.0400',
        },
    },
    's390x: qeth adapter with MAC address and device number',
);
my $qm = $mf->{qm};
is($qm->{machine}, 'czam', 's390x: machine type');
is($qm->{ipl}, 'ckd0', 's390x: IPL device');
is($qm->{boot}, 'order=ckd0;net0', 's390x: boot order');
is($qm->{ostype}, 'other', 's390x: OS type');
is($qm->{memory}, '2048', 's390x: memory');
is($qm->{name}, 'mf01', 's390x: name');
is($qm->{tape0}, 'local:iso/SYSTEM.AWS', 's390x: tape drive');
ok(!exists($qm->{scsihw}), 's390x: no SCSI controller without SCSI disks');
is_deeply(
    [map { $qm->{"terminal$_"} } 0 .. 2],
    [qw(0.0.0300 0.0.0301 0.0.0302)],
    's390x: 3270 terminals',
);
is_deeply($mf->{warnings} // [], [], 's390x: no warnings');

# the same OVA on another architecture: generic mapping
my $mf_x86 = PVE::GuestImport::OVF::parse_ovf($mf_ova, 1, 0, 'x86_64');
is_deeply(
    [map { $_->{disk_address} } $mf_x86->{disks}->@*],
    [qw(sata0 sata1 sata2)],
    'x86_64: DASDs as SATA disks',
);
ok(!defined($mf_x86->{qm}->{machine}), 'x86_64: no s390x machine type');
is($mf_x86->{net}->{net0}->{model}, 'e1000', 'x86_64: qeth adapter as e1000');
is_deeply(
    $mf_x86->{warnings},
    [{ type => 'foreign-architecture', key => 'arch', value => 's390x' }],
    'x86_64: foreign architecture warning',
);

my $linux = PVE::GuestImport::OVF::parse_ovf(make_ova('pve-linux-x86_64.ovf'), 1, 0, 'x86_64');
is_deeply(
    [map { $_->{disk_address} } $linux->{disks}->@*],
    [qw(scsi0 virtio1)],
    'Linux: SCSI and VirtIO disks',
);
is_deeply(
    $linux->{disks}->[0]->{options},
    { discard => 'on', iothread => '1' },
    'Linux: disk options',
);
is($linux->{qm}->{bios}, 'ovmf', 'Linux: OVMF');
is($linux->{qm}->{scsihw}, 'virtio-scsi-single', 'Linux: SCSI controller');
is($linux->{qm}->{serial0}, 'socket', 'Linux: serial port');
is($linux->{qm}->{cores}, '2', 'Linux: cores');
is_deeply(
    $linux->{net}->{net0},
    {
        model => 'virtio',
        macaddr => 'BC:24:11:00:00:01',
        bridge => 'vmbr0',
        firewall => '1',
        tag => '10',
    },
    'Linux: VirtIO NIC',
);

# a hostile section: only harmless keys and options get through
my $hostile_ovf = PVE::Tools::file_get_contents("$test_manifests/pve-linux-x86_64.ovf");
$hostile_ovf =~ s{(<pve:Config pve:key="bios")}{
    <pve:Config pve:key="hookscript" pve:value="local:snippets/evil.pl"/>
    <pve:Config pve:key="args" pve:value="-drive file=/etc/shadow"/>
    <pve:Config pve:key="serial1" pve:value="/dev/ttyS0"/>
    <pve:Config pve:key="hostpci0" pve:value="0000:01:00.0"/>
    <pve:Config pve:key="scsi5" pve:value="/dev/sda" pve:diskId="nonexistent"/>
    <pve:Config pve:key="tape1" pve:value="local:iso/x.aws,devno=0.0.0581&#10;args: -foo"/>
    <pve:Config pve:key="virtio9" pve:value="file=/etc/shadow,cache=unsafe;x" pve:diskId="virtio1"/>
    $1};
mkdir "$tmpdir/hostile";
PVE::Tools::file_set_contents("$tmpdir/hostile/hostile.ovf", $hostile_ovf);
system('tar', '-cf', "$tmpdir/hostile.ova", '-C', "$tmpdir/hostile", 'hostile.ovf') == 0 or die;
my $hostile = eval {
    local $SIG{__WARN__} = sub { };
    PVE::GuestImport::OVF::parse_ovf("$tmpdir/hostile.ova", 1, 0, 'x86_64');
};
is($@, '', 'hostile: parsed');
ok(
    !(grep { defined($hostile->{qm}->{$_}) } qw(hookscript args serial1 hostpci0 tape1 scsi5)),
    'hostile: no hookscript, args, host devices or multi-line values',
);
is_deeply(
    [map { $_->{disk_address} } $hostile->{disks}->@*],
    [qw(scsi0 virtio9)],
    'hostile: a disk can be renamed, but not get new volumes',
);
ok(!defined($hostile->{disks}->[1]->{options}->{file}), 'hostile: no file option for a disk');

done_testing();
