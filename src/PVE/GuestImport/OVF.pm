# Open Virtualization Format import routines
# https://www.dmtf.org/standards/ovf
package PVE::GuestImport::OVF;

use strict;
use warnings;

use XML::LibXML;
use File::Spec;
use File::Basename;
use Cwd 'realpath';

use PVE::Tools;
use PVE::Storage;
use PVE::Seccomp qw(stmt /^BPF_/);

# Namespace of the Proxmox VE configuration section in OVF descriptors written by Proxmox VE (see
# PVE::QemuServer::OVA). The section carries the guest configuration that OVF has no resource
# types for, so a Proxmox VE host recreates the guest as it was exported: VirtIO devices, machine
# type, s390x DASDs, tape drives, 3270 terminals and device numbers, for example. Other OVF
# consumers ignore it (ovf:required="false").
our $PVE_OVF_NS = 'http://www.proxmox.com/schema/ovf';
our $PVE_OVF_SECTION_VERSION = 1;

# map OVF resources types to descriptive strings
# this will allow us to explore the xml tree without using magic numbers
# http://schemas.dmtf.org/wbem/cim-html/2/CIM_ResourceAllocationSettingData.html
my @resources = (
    { id => 1, dtmf_name => 'Other' },
    { id => 2, dtmf_name => 'Computer System' },
    { id => 3, dtmf_name => 'Processor' },
    { id => 4, dtmf_name => 'Memory' },
    { id => 5, dtmf_name => 'IDE Controller', pve_type => 'ide' },
    { id => 6, dtmf_name => 'Parallel SCSI HBA', pve_type => 'scsi' },
    { id => 7, dtmf_name => 'FC HBA' },
    { id => 8, dtmf_name => 'iSCSI HBA' },
    { id => 9, dtmf_name => 'IB HCA' },
    { id => 10, dtmf_name => 'Ethernet Adapter' },
    { id => 11, dtmf_name => 'Other Network Adapter' },
    { id => 12, dtmf_name => 'I/O Slot' },
    { id => 13, dtmf_name => 'I/O Device' },
    { id => 14, dtmf_name => 'Floppy Drive' },
    { id => 15, dtmf_name => 'CD Drive' },
    { id => 16, dtmf_name => 'DVD drive' },
    { id => 17, dtmf_name => 'Disk Drive' },
    { id => 18, dtmf_name => 'Tape Drive' },
    { id => 19, dtmf_name => 'Storage Extent' },
    { id => 20, dtmf_name => 'Other storage device', pve_type => 'sata' },
    { id => 21, dtmf_name => 'Serial port' },
    { id => 22, dtmf_name => 'Parallel port' },
    { id => 23, dtmf_name => 'USB Controller' },
    { id => 24, dtmf_name => 'Graphics controller' },
    { id => 25, dtmf_name => 'IEEE 1394 Controller' },
    { id => 26, dtmf_name => 'Partitionable Unit' },
    { id => 27, dtmf_name => 'Base Partitionable Unit' },
    { id => 28, dtmf_name => 'Power' },
    { id => 29, dtmf_name => 'Cooling Capacity' },
    { id => 30, dtmf_name => 'Ethernet Switch Port' },
    { id => 31, dtmf_name => 'Logical Disk' },
    { id => 32, dtmf_name => 'Storage Volume' },
    { id => 33, dtmf_name => 'Ethernet Connection' },
    { id => 34, dtmf_name => 'DMTF reserved' },
    { id => 35, dtmf_name => 'Vendor Reserved' },
);

# see https://schemas.dmtf.org/wbem/cim-html/2.55.0+/CIM_OperatingSystem.html
my $ostype_ids = {
    18 => 'winxp', # 'WINNT',
    29 => 'solaris', # 'Solaris',
    36 => 'l26', # 'LINUX',
    58 => 'w2k', # 'Windows 2000',
    67 => 'wxp', #'Windows XP',
    69 => 'w2k3', # 'Microsoft Windows Server 2003',
    70 => 'w2k3', # 'Microsoft Windows Server 2003 64-Bit',
    71 => 'wxp', # 'Windows XP 64-Bit',
    72 => 'wxp', # 'Windows XP Embedded',
    73 => 'wvista', # 'Windows Vista',
    74 => 'wvista', # 'Windows Vista 64-Bit',
    75 => 'wxp', # 'Windows Embedded for Point of Service', ??
    76 => 'w2k8', # 'Microsoft Windows Server 2008',
    77 => 'w2k8', # 'Microsoft Windows Server 2008 64-Bit',
    79 => 'l26', # 'RedHat Enterprise Linux',
    80 => 'l26', # 'RedHat Enterprise Linux 64-Bit',
    81 => 'solaris', #'Solaris 64-Bit',
    82 => 'l26', # 'SUSE',
    83 => 'l26', # 'SUSE 64-Bit',
    84 => 'l26', # 'SLES',
    85 => 'l26', # 'SLES 64-Bit',
    87 => 'l26', # 'Novell Linux Desktop',
    89 => 'l26', # 'Mandriva',
    90 => 'l26', # 'Mandriva 64-Bit',
    91 => 'l26', # 'TurboLinux',
    92 => 'l26', # 'TurboLinux 64-Bit',
    93 => 'l26', # 'Ubuntu',
    94 => 'l26', # 'Ubuntu 64-Bit',
    95 => 'l26', # 'Debian',
    96 => 'l26', # 'Debian 64-Bit',
    97 => 'l24', # 'Linux 2.4.x',
    98 => 'l24', # 'Linux 2.4.x 64-Bit',
    99 => 'l26', # 'Linux 2.6.x',
    100 => 'l26', # 'Linux 2.6.x 64-Bit',
    101 => 'l26', # 'Linux 64-Bit',
    103 => 'win7', # 'Microsoft Windows Server 2008 R2',
    105 => 'win7', # 'Microsoft Windows 7',
    106 => 'l26', # 'CentOS 32-bit',
    107 => 'l26', # 'CentOS 64-bit',
    108 => 'l26', # 'Oracle Linux 32-bit',
    109 => 'l26', # 'Oracle Linux 64-bit',
    111 => 'win8', # 'Microsoft Windows Server 2011', ??
    112 => 'win8', # 'Microsoft Windows Server 2012',
    113 => 'win8', # 'Microsoft Windows 8',
    114 => 'win8', # 'Microsoft Windows 8 64-bit',
    115 => 'win8', # 'Microsoft Windows Server 2012 R2',
    116 => 'win10', # 'Microsoft Windows Server 2016',
    117 => 'win8', # 'Microsoft Windows 8.1',
    118 => 'win8', # 'Microsoft Windows 8.1 64-bit',
    119 => 'win10', # 'Microsoft Windows 10',
    120 => 'win10', # 'Microsoft Windows 10 64-bit',
    121 => 'win10', # 'Microsoft Windows Server 2019',
    122 => 'win11', # 'Microsoft Windows 11 64-bit',
    123 => 'win11', # 'Microsoft Windows Server 2022',
    # others => 'other',
};

sub get_ostype {
    my ($id) = @_;

    return $ostype_ids->{$id} // 'other';
}

my $allowed_nic_models = [
    'e1000', 'e1000e', 'vmxnet3',
];

sub find_by {
    my ($key, $param) = @_;
    foreach my $resource (@resources) {
        if ($resource->{$key} eq $param) {
            return ($resource);
        }
    }
    return;
}

sub dtmf_name_to_id {
    my ($dtmf_name) = @_;
    my $found = find_by('dtmf_name', $dtmf_name);
    if ($found) {
        return $found->{id};
    } else {
        return;
    }
}

sub id_to_pve {
    my ($id) = @_;
    my $resource = find_by('id', $id);
    if ($resource) {
        return $resource->{pve_type};
    } else {
        return;
    }
}

# technically defined in DSP0004 (https://www.dmtf.org/dsp/DSP0004) as an ABNF
# but realistically this always takes the form of 'byte * base^exponent'
sub try_parse_capacity_unit {
    my ($unit_text) = @_;

    if ($unit_text =~ m/^\s*byte\s*\*\s*([0-9]+)\s*\^\s*([0-9]+)\s*$/) {
        my $base = $1;
        my $exp = $2;
        return $base**$exp;
    }
    return 1 if $unit_text =~ m/^\s*byte\s*$/; # sizes that are not whole KiB, like CKD volumes

    return undef;
}

my sub read_ovf_file {
    my ($ovf, $isOva) = @_;

    return PVE::Tools::file_get_contents($ovf) if !$isOva;

    my $raw = "";
    PVE::Tools::run_command(
        ['tar', '-xO', '--wildcards', '--occurrence=1', '-f', $ovf, '--', '*.ovf'],
        outfunc => sub {
            my $line = shift;
            $raw .= $line;
        },
    );
    return $raw;
}

# returns two references, $qm which holds qm.conf style key/values, and \@disks
my sub parse_ovf_do {
    my ($ovf, $ovf_data, $isOva, $debug) = @_;

    # we have to ignore missing disk images for ova
    my $dom = XML::LibXML->load_xml(string => $ovf_data, no_blanks => 1);

    # register the xml namespaces in a xpath context object
    # 'ovf' is the default namespace so it will prepended to each xml element
    my $xpc = XML::LibXML::XPathContext->new($dom);
    $xpc->registerNs('ovf', 'http://schemas.dmtf.org/ovf/envelope/1');
    $xpc->registerNs('vmw', 'http://www.vmware.com/schema/ovf');
    $xpc->registerNs('pve', $PVE_OVF_NS);
    $xpc->registerNs(
        'rasd',
        'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData',
    );
    $xpc->registerNs(
        'vssd',
        'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData',
    );

    # hash to save qm.conf parameters
    my $qm;

    #array to save a disk list
    my @disks;

    # easy xpath
    # walk down the dom until we find the matching XML element
    my $ovf_name = $xpc->findvalue("/ovf:Envelope/ovf:VirtualSystem/ovf:Name");
    if (!$ovf_name) {
        # this is a bit of a hack, but best-effort and can only win here
        my @nodes = $xpc->findnodes("/ovf:Envelope/ovf:VirtualSystem");
        if (my $virtual_system_node = shift @nodes) {
            for my $attr ($virtual_system_node->attributes()) {
                if ($attr->nodeName() eq 'ovf:id') {
                    $ovf_name = $attr->getValue();
                    last;
                }
            }
        }
    }
    if ($ovf_name) {
        # PVE::QemuServer::confdesc requires a valid DNS name
        $ovf_name =~ s/\s+/-/g;
        ($qm->{name} = $ovf_name) =~ s/[^a-zA-Z0-9\-\.]//g;
    } else {
        warn
            "warning: unable to parse the VM name in this OVF manifest, generating a default value\n";
    }

    # middle level xpath
    # element[child] search the elements which have this [child]
    my $processor_id = dtmf_name_to_id('Processor');
    my $xpath_find_vcpu_count =
        "/ovf:Envelope/ovf:VirtualSystem/ovf:VirtualHardwareSection/ovf:Item[rasd:ResourceType=${processor_id}]/rasd:VirtualQuantity";
    $qm->{'cores'} = $xpc->findvalue($xpath_find_vcpu_count);

    my $memory_id = dtmf_name_to_id('Memory');
    my $xpath_find_memory = (
        "/ovf:Envelope/ovf:VirtualSystem/ovf:VirtualHardwareSection/ovf:Item[rasd:ResourceType=${memory_id}]/rasd:VirtualQuantity"
    );
    $qm->{'memory'} = $xpc->findvalue($xpath_find_memory);

    # middle level xpath
    # here we expect multiple results, so we do not read the element value with
    # findvalue() but store multiple elements with findnodes()
    my $disk_id = dtmf_name_to_id('Disk Drive');
    my $xpath_find_disks =
        "/ovf:Envelope/ovf:VirtualSystem/ovf:VirtualHardwareSection/ovf:Item[rasd:ResourceType=${disk_id}]";
    my @disk_items = $xpc->findnodes($xpath_find_disks);

    my $xpath_find_ostype_id =
        "/ovf:Envelope/ovf:VirtualSystem/ovf:OperatingSystemSection/\@ovf:id";
    my $ostype_id = $xpc->findvalue($xpath_find_ostype_id);
    $qm->{ostype} = get_ostype($ostype_id);

    # vmware specific firmware config, seems to not be standardized in ovf ?
    my $xpath_find_firmware =
        "/ovf:Envelope/ovf:VirtualSystem/ovf:VirtualHardwareSection/vmw:Config[\@vmw:key=\"firmware\"]/\@vmw:value";
    my $firmware = $xpc->findvalue($xpath_find_firmware) || 'seabios';
    $qm->{bios} = 'ovmf' if $firmware eq 'efi';

    # disks metadata is split in four different xml elements:
    # * as an Item node of type DiskDrive in the VirtualHardwareSection
    # * as an Disk node in the DiskSection
    # * as a File node in the References section
    # * each Item node also holds a reference to its owning controller
    #
    # we iterate over the list of Item nodes of type disk drive, and for each item,
    # find the corresponding Disk node, and File node and owning controller
    # when all the nodes has been found out, we copy the relevant information to
    # a $pve_disk hash ref, which we push to @disks;

    for my $item_node (@disk_items) {
        my ($disk_node, $file_node, $controller_node, $pve_disk);

        print "disk item:\n", $item_node->toString(1), "\n" if $debug;

        # from Item, find corresponding Disk node
        # here the dot means the search should start from the current element in dom
        my $host_resource = $xpc->findvalue('rasd:HostResource', $item_node);
        my $disk_section_path;
        my $disk_id;

        # RFC 3986 "2.3.  Unreserved Characters"
        my $valid_uripath_chars = qr/[[:alnum:]]|[\-\._~]/;

        if ($host_resource =~ m|^(?:ovf:)?/(${valid_uripath_chars}+)/(${valid_uripath_chars}+)$|) {
            $disk_section_path = $1;
            $disk_id = $2;
        } else {
            warn "invalid host resource $host_resource, skipping\n";
            next;
        }
        printf "disk section path: $disk_section_path and disk id: $disk_id\n" if $debug;

        # tricky xpath
        # @ means we filter the result query based on a the value of an item attribute ( @ = attribute)
        # @ needs to be escaped to prevent Perl double quote interpolation
        my $xpath_find_fileref = sprintf(
            "/ovf:Envelope/ovf:DiskSection/\
ovf:Disk[\@ovf:diskId='%s']/\@ovf:fileRef", $disk_id,
        );
        my $xpath_find_capacity = sprintf(
            "/ovf:Envelope/ovf:DiskSection/\
ovf:Disk[\@ovf:diskId='%s']/\@ovf:capacity", $disk_id,
        );
        my $xpath_find_capacity_unit = sprintf(
            "/ovf:Envelope/ovf:DiskSection/\
ovf:Disk[\@ovf:diskId='%s']/\@ovf:capacityAllocationUnits", $disk_id,
        );
        my $fileref = $xpc->findvalue($xpath_find_fileref);
        my $capacity = $xpc->findvalue($xpath_find_capacity);
        my $capacity_unit = $xpc->findvalue($xpath_find_capacity_unit);
        my $virtual_size;
        if (my $factor = try_parse_capacity_unit($capacity_unit)) {
            $virtual_size = $capacity * $factor;
        }

        my $valid_url_chars = qr@${valid_uripath_chars}|/@;
        if (!$fileref || $fileref !~ m/^${valid_url_chars}+$/) {
            warn "invalid host resource $host_resource, skipping\n";
            next;
        }

        # from Item, find owning Controller type
        my $controller_id = $xpc->findvalue('rasd:Parent', $item_node);
        my $xpath_find_parent_type = sprintf(
            "/ovf:Envelope/ovf:VirtualSystem/ovf:VirtualHardwareSection/\
ovf:Item[rasd:InstanceID='%s']/rasd:ResourceType", $controller_id,
        );
        my $controller_type = $xpc->findvalue($xpath_find_parent_type);
        if (!$controller_type) {
            warn "invalid or missing controller: $controller_type, skipping\n";
            next;
        }
        print "owning controller type: $controller_type\n" if $debug;

        # extract corresponding Controller node details
        my $adress_on_controller = $xpc->findvalue('rasd:AddressOnParent', $item_node);
        my $pve_disk_address = id_to_pve($controller_type) . $adress_on_controller;

        # from Disk Node, find corresponding filepath
        my $xpath_find_filepath =
            sprintf("/ovf:Envelope/ovf:References/ovf:File[\@ovf:id='%s']/\@ovf:href", $fileref);
        my $filepath = $xpc->findvalue($xpath_find_filepath);
        if (!$filepath) {
            warn "invalid file reference $fileref, skipping\n";
            next;
        }
        print "file path: $filepath\n" if $debug;
        my $original_filepath = $filepath;
        ($filepath) = $filepath =~ m|^(${PVE::Storage::SAFE_CHAR_WITH_WHITESPACE_CLASS_RE}+)$|; # untaint & check no sub/parent dirs
        die "referenced path '$original_filepath' is invalid\n"
            if !$filepath || $filepath eq "." || $filepath eq "..";

        push @disks,
            {
                filepath => $filepath,
                virtual_size => $virtual_size,
                disk_address => $pve_disk_address,
                disk_id => $disk_id,
            };
    }

    my $nic_id = dtmf_name_to_id('Ethernet Adapter');
    my $xpath_find_nics =
        "/ovf:Envelope/ovf:VirtualSystem/ovf:VirtualHardwareSection/ovf:Item[rasd:ResourceType=${nic_id}]";
    my @nic_items = $xpc->findnodes($xpath_find_nics);

    my $net = {};

    my $net_count = 0;
    for my $item_node (@nic_items) {
        my $model = $xpc->findvalue('rasd:ResourceSubType', $item_node);
        $model = lc($model);
        $model = 'e1000' if !grep { $_ eq $model } @$allowed_nic_models;
        $net->{"net${net_count}"} = { model => $model };
        $net_count++;
    }

    # the Proxmox VE configuration section, interpreted in apply_pve_section()
    my $pve;
    my ($pve_section) = $xpc->findnodes('/ovf:Envelope/ovf:VirtualSystem/pve:ConfigSection');
    if ($pve_section) {
        $pve = {
            version => $pve_section->getAttributeNS($PVE_OVF_NS, 'version'),
            arch => $pve_section->getAttributeNS($PVE_OVF_NS, 'arch'),
            config => [],
        };
        for my $node ($xpc->findnodes('pve:Config', $pve_section)) {
            my $entry = {};
            for my $attr (qw(key value diskId)) {
                my $value = $node->getAttributeNS($PVE_OVF_NS, $attr);
                $entry->{$attr} = $value if defined($value);
            }
            push $pve->{config}->@*, $entry;
        }
    }

    return { qm => $qm, disks => \@disks, net => $net, pve => $pve };
}

# The configuration keys taken from the Proxmox VE section, with a check of the value. The values
# are checked once more by the VM creation API, this only keeps out what must not come from an
# untrusted archive (host paths, hook scripts, pass-through devices, ...).
my $pve_simple_value_re = qr/^[A-Za-z0-9\-_.:=,;+\/ ]*$/;
my $pve_config_keys = {
    (
        map { $_ => $pve_simple_value_re }
            qw(
            acpi agent balloon bios boot cores cpu cpuunits ipl keyboard kvm localtime machine memory
            numa ostype scsihw shares sockets tablet vcpus vga
            )
    ),
    description => qr/^.*$/s,
    tags => $pve_simple_value_re,
};
my $pve_config_key_patterns = [
    [qr/^terminal\d+$/, $pve_simple_value_re],
    [qr/^tape\d+$/, $pve_simple_value_re],
    [qr/^serial\d+$/, qr/^socket$/],
    [qr/^numa\d+$/, $pve_simple_value_re],
];

# Options of disks and network devices that are taken over. A disk also gets 'import-from', a NIC
# its bridge from the import.
my $pve_drive_options = {
    map { $_ => 1 }
        qw(
        aio backup cache devno discard iothread model name replicate ro serial ssd wwn
        )
};
my $pve_drive_key_re = qr/^(?:ide|sata|scsi|virtio|fba|ckd)\d+$/;

my $pve_net_options = { map { $_ => 1 }
    qw(bridge devno firewall link_down macaddr model mtu queues rate tag trunks) };

my sub pve_section_value_ok {
    my ($key, $value) = @_;

    return 0 if !defined($value);
    if (my $re = $pve_config_keys->{$key}) {
        return $value =~ $re;
    }
    for my $pattern (@$pve_config_key_patterns) {
        my ($key_re, $value_re) = @$pattern;
        return $value =~ $value_re if $key =~ $key_re;
    }
    return 0;
}

# Split a property string like 'qeth=BC:24:11:00:00:01,bridge=vmbr0' into its key=value pairs. A
# leading bare value or 'model=mac' pair is returned under the key '' and as model/macaddr.
my sub split_property_string {
    my ($value) = @_;

    my $res = {};
    for my $part (split(/,/, $value)) {
        if ($part =~ m/^([a-z][a-z0-9_\-]*)=(.*)$/) {
            $res->{$1} = $2;
        } elsif (!defined($res->{''})) {
            $res->{''} = $part;
        }
    }
    return $res;
}

# Apply the Proxmox VE configuration section to the parsed OVF ($res as parse_ovf_do returns it).
# Only for the architecture it was written for: a guest exported from another architecture gets
# the generic OVF mapping and a 'foreign-architecture' warning.
my sub apply_pve_section {
    my ($res, $host_arch) = @_;

    my $pve = delete $res->{pve} or return;
    my $warnings = $res->{warnings} //= [];

    my $version = $pve->{version} // '';
    if ($version !~ m/^\d+$/ || $version > $PVE_OVF_SECTION_VERSION) {
        warn "ignoring Proxmox VE configuration section of unsupported version '$version'\n";
        return;
    }

    my $arch = $pve->{arch} // 'x86_64';
    if ($arch ne $host_arch) {
        push @$warnings, { type => 'foreign-architecture', key => 'arch', value => $arch };
        return;
    }

    my $disks_by_id = { map { ($_->{disk_id} // '') => $_ } $res->{disks}->@* };
    my $qm = $res->{qm};
    my $net = {};
    my $drive_keys = {};
    my $assigned_disks = {};
    my $boot;

    for my $entry ($pve->{config}->@*) {
        my ($key, $value, $disk_id) = $entry->@{qw(key value diskId)};
        next if !defined($key) || !defined($value);

        if ($key =~ $pve_drive_key_re) {
            # a disk that is in the archive, its options
            next if !defined($disk_id) || $drive_keys->{$key} || $assigned_disks->{$disk_id};
            my $disk = $disks_by_id->{$disk_id} or next;
            $assigned_disks->{$disk_id} = 1;
            my $props = split_property_string($value);
            my $options = {};
            for my $opt (sort keys %$props) {
                next if !$pve_drive_options->{$opt};
                next if $props->{$opt} !~ m/^[A-Za-z0-9\-_.:]+$/;
                $options->{$opt} = $props->{$opt};
            }
            $disk->{disk_address} = $key;
            $disk->{options} = $options if scalar(keys %$options);
            $drive_keys->{$key} = 1;
        } elsif ($key =~ m/^net\d+$/) {
            my $props = split_property_string($value);
            my $nic = {};
            for my $opt (sort keys %$props) {
                my $v = $props->{$opt};
                next if $v !~ m/^[A-Za-z0-9\-_.:;]+$/;
                if ($pve_net_options->{$opt}) {
                    $nic->{$opt} = $v;
                } elsif (
                    $opt =~ m/^[a-z][a-z0-9\-]*$/
                    && $v =~ m/^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$/
                ) {
                    # '<model>=<mac>'
                    $nic->@{qw(model macaddr)} = ($opt, $v) if !defined($nic->{model});
                }
            }
            $nic->{model} //= $props->{''};
            next if !defined($nic->{model}) || $nic->{model} !~ m/^[a-z][a-z0-9\-]*$/;
            $net->{$key} = $nic;
        } elsif ($key eq 'boot') {
            $boot = $value if pve_section_value_ok($key, $value);
        } elsif (pve_section_value_ok($key, $value)) {
            $qm->{$key} = $value;
        } else {
            warn "ignoring '$key' from the Proxmox VE configuration section\n";
        }
    }

    $res->{net} = $net if scalar(keys %$net);
    $res->{boot} = $boot if defined($boot);

    # an s390x VM (mostly DASDs) only needs the SCSI controller for SCSI disks
    my $has_scsi_disks = grep { ($_->{disk_address} // '') =~ m/^scsi\d+$/ } $res->{disks}->@*;
    delete $qm->{scsihw} if $arch eq 's390x' && !$has_scsi_disks;

    return;
}

my sub resolve_disks {
    my ($ovf, $qm, $isOva) = @_;

    my $boot_order = [];

    my $parsed_disks = delete($qm->{disks});

    my @disks;
    for my $disk (@$parsed_disks) {
        my $filepath = $disk->{filepath};
        my $virtual_size = $disk->{virtual_size};
        my $pve_disk_address = $disk->{disk_address};
        my $options = $disk->{options};

        # resolve symlinks and relative path components
        # and die if the diskimage is not somewhere under the $ovf path
        my $ovf_dir = realpath(dirname(File::Spec->rel2abs($ovf)))
            or die "could not get absolute path of $ovf: $!\n";
        my $backing_file_path = realpath(join('/', $ovf_dir, $filepath))
            or die "could not get absolute path of $filepath: $!\n";
        if ($backing_file_path !~ /^\Q${ovf_dir}\E/) {
            die "error parsing $filepath, are you using a symlink ?\n";
        }

        ($backing_file_path) = $backing_file_path =~ m|^(/.*)|; # untaint

        if (!-e $backing_file_path && !$isOva) {
            die "error parsing $filepath, file seems not to exist at $backing_file_path\n";
        }

        if (!$isOva) {
            my $size = PVE::Storage::file_size_info($backing_file_path, undef, 'auto-detect');
            die "error parsing $backing_file_path, cannot determine file size\n"
                if !$size;

            $virtual_size = $size;
        }

        my $pve_disk = {
            disk_address => $pve_disk_address,
            backing_file => $backing_file_path,
            virtual_size => $virtual_size,
            relative_path => $filepath,
        };
        $pve_disk->{virtual_size} = $virtual_size if defined($virtual_size);
        $pve_disk->{options} = $options if defined($options);
        push @disks, $pve_disk;
        push @$boot_order, $pve_disk_address;
    }

    if (defined(my $boot = delete $qm->{boot})) {
        $qm->{qm}->{boot} = $boot;
    } elsif (scalar(@$boot_order) > 0) {
        $qm->{qm}->{boot} = "order=" . join(';', @$boot_order);
    }

    $qm->{disks} = \@disks;
    return;
}

my sub bpf_prog {
    return [
        stmt(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
        stmt(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, PVE::Syscall::write),
        stmt(BPF_JMP | BPF_JEQ | BPF_K, 3, 0, PVE::Syscall::exit),
        stmt(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, PVE::Syscall::exit_group),
        stmt(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, PVE::Syscall::brk),
        stmt(BPF_RET | BPF_K, 0, 0, BPF_RET_KILL), # default: no syscall matched, kill the process
        stmt(BPF_RET | BPF_K, 0, 0, BPF_RET_ALLOW), # a syscall above matched, allow it
    ];
}

sub parse_ovf {
    my ($ovf, $isOva, $debug, $host_arch) = @_;

    my $qm = PVE::Tools::run_fork_with_timeout(
        3,
        sub {
            my $ovf_data = read_ovf_file($ovf, $isOva);

            PVE::Seccomp::set_no_new_privs();
            PVE::Seccomp::set_filter(bpf_prog());

            return parse_ovf_do($ovf, $ovf_data, $isOva, $debug);
        },
    );

    if (!$qm) {
        die "OVF parser terminated unexpectedly trying to parse $ovf\n";
    }

    apply_pve_section($qm, $host_arch // PVE::Tools::get_host_arch());
    resolve_disks($ovf, $qm, $isOva);

    return $qm;
}

1;
