package PVE::GuestImport;

use strict;
use warnings;

use File::Path;

use PVE::Storage;
use PVE::Tools qw(run_command);

sub extract_disk_from_import_file {
    my ($volid, $vmid, $target_storeid) = @_;

    my ($source_storeid, $volname) = PVE::Storage::parse_volume_id($volid);
    $target_storeid //= $source_storeid;
    my $cfg = PVE::Storage::config();

    my ($vtype, $name, undef, undef, undef, undef, $fmt) =
        PVE::Storage::parse_volname($cfg, $volid);

    die "only files with content type 'import' can be extracted\n"
        if $vtype ne 'import';

    die "only files from 'ova' format can be extracted\n"
        if $fmt !~ m/^ova\+/;

    # extract the inner file from the name
    my $archive_volid;
    my $inner_file;
    my $inner_fmt;
    if ($name =~ m!^(.*\.ova)/(${PVE::Storage::SAFE_CHAR_WITH_WHITESPACE_CLASS_RE}+)$!) {
        $archive_volid = "$source_storeid:import/$1";
        $inner_file = $2;
        ($inner_fmt) = $fmt =~ /^ova\+(.*)$/;
    } else {
        die "cannot extract $volid - invalid volname $volname\n";
    }

    die "cannot determine format of '$volid'\n" if !$inner_fmt;
    die "'$volid' is a tape medium, not a disk image\n" if $inner_fmt eq 'aws';

    my $ova_path = PVE::Storage::path($cfg, $archive_volid);

    my $tmpdir = PVE::Storage::get_image_dir($cfg, $target_storeid, $vmid);
    my $pid = $$;
    $tmpdir .= "/tmp_${pid}_${vmid}";
    mkpath $tmpdir;

    my $source_path = "$tmpdir/$inner_file";
    my $target_path;
    my $target_volid;
    eval {
        run_command([
            'tar',
            '-x',
            '--force-local',
            '--no-same-owner',
            '-C',
            $tmpdir,
            '-f',
            $ova_path,
            '--',
            $inner_file,
        ]);

        # check for symlinks and other non regular files
        if (-l $source_path || !-f $source_path) {
            die
                "extracted file '$inner_file' from archive '$archive_volid' is not a regular file\n";
        }

        # check potentially untrusted image file!
        PVE::Storage::file_size_info($source_path, undef, $inner_fmt, 1);

        # create temporary 1M image that will get overwritten by the rename
        # to reserve the filename and take care of locking
        $target_volid =
            PVE::Storage::vdisk_alloc($cfg, $target_storeid, $vmid, $inner_fmt, undef, 1024);
        $target_path = PVE::Storage::path($cfg, $target_volid);

        print "renaming $source_path to $target_path\n";

        rename($source_path, $target_path) or die "unable to move - $!\n";
    };
    if (my $err = $@) {
        File::Path::remove_tree($tmpdir);
        die "error during extraction: $err\n";
    }

    File::Path::remove_tree($tmpdir);

    return $target_volid;
}

# Extract a tape medium (an AWSTAPE image) from an OVA ('<storage>:import/<x>.ova/<file>.aws') into
# the ISO images content of storage $target_storeid, where tape media live. The medium keeps its
# file name. If a file of that name is there already, it is used if it has the same content, else
# the medium gets a free name '<name>-<n>.aws'. Returns the volume ID of the medium.
sub extract_media_from_import_file {
    my ($volid, $target_storeid) = @_;

    my $cfg = PVE::Storage::config();
    my ($source_storeid) = PVE::Storage::parse_volume_id($volid);
    my ($vtype, $name, undef, undef, undef, undef, $fmt) =
        PVE::Storage::parse_volname($cfg, $volid);

    die "only files with content type 'import' can be extracted\n" if $vtype ne 'import';
    die "'$volid' is not a tape medium (.aws) in an OVA\n" if $fmt ne 'ova+aws';
    my ($archive, $inner_file) =
        $name =~ m!^(.*\.ova)/(${PVE::Storage::SAFE_CHAR_WITH_WHITESPACE_CLASS_RE}+)$!
        or die "cannot extract $volid - invalid volume name\n";
    my $ova_path = PVE::Storage::path($cfg, "$source_storeid:import/$archive");

    my $scfg = PVE::Storage::storage_config($cfg, $target_storeid);
    die "storage '$target_storeid' does not have the 'iso' content type for tape media\n"
        if !$scfg->{content}->{iso};
    PVE::Storage::activate_storage($cfg, $target_storeid);
    my $iso_dir = PVE::Storage::get_iso_dir($cfg, $target_storeid);
    mkpath $iso_dir;

    my $tmpdir = "$iso_dir/.import-tmp-$$";
    mkpath $tmpdir;
    my $res;
    eval {
        run_command([
            'tar',
            '-x',
            '--force-local',
            '--no-same-owner',
            '-C',
            $tmpdir,
            '-f',
            $ova_path,
            '--',
            $inner_file,
        ]);
        my $source_path = "$tmpdir/$inner_file";
        die "extracted file '$inner_file' from '$ova_path' is not a regular file\n"
            if -l $source_path || !-f $source_path;

        (my $base = $inner_file) =~ s/\s+/_/g;
        my ($stem, $ext) = $base =~ m/^(.*?)(\.[^.]+)$/;
        for my $n (0 .. 999) {
            my $file = $n ? "$stem-$n$ext" : $base;
            my $target = "$iso_dir/$file";
            if (-e $target) {
                my $same = eval {
                    run_command(['cmp', '-s', '--', $source_path, $target]);
                    1;
                };
                if ($same) {
                    print "tape medium '$file' is on storage '$target_storeid' already\n";
                    $res = "$target_storeid:iso/$file";
                    last;
                }
                next;
            }
            # link() does not replace a file that appeared meanwhile, unlike rename()
            if (link($source_path, $target)) {
                print "extracted tape medium '$inner_file' to '$target_storeid:iso/$file'\n";
                $res = "$target_storeid:iso/$file";
                last;
            }
            die "unable to create '$target' - $!\n" if !$!{EEXIST};
        }
        die "no free name for the tape medium '$inner_file' on storage '$target_storeid'\n"
            if !defined($res);
    };
    my $err = $@;
    File::Path::remove_tree($tmpdir);
    die "error extracting tape medium: $err" if $err;

    return $res;
}

1;
