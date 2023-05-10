#------------------------------------------------------------------------------
# File:         7z.pm
#
# Description:  Read 7z archive meta information
#
# Revisions:    04/28/2023 - AmirGooran (Cyberno)
#
# References:   1) https://py7zr.readthedocs.io/en/latest/archive_format.html
#------------------------------------------------------------------------------


package Image::ExifTool::7z;

use strict;

use Data::Dumper;


sub ReadUInt32 {
    my $buff;
    
    $_[0]->Read($buff, 4);
    my ($output) = unpack('L', $buff);
    return $output;
}


sub ReadUInt64 {
    my $buff;
    my $output;
    
    $_[0]->Read($buff, 1);
    my $b = ord($buff);
    if($b == 255){  # read real uint64
        $_[0]->Read($buff, 8);
        my ($output) = unpack('Q', $buff);
        return $output;
    }
    my @blen = (0x7F, 0xBF, 0xDF, 0xEF, 0xF7, 0xFB, 0xFD, 0xFE);
    
    my $mask = 0x80;
    my $vlen = 8;
    
    for (my $l = 0 ; $l < scalar(@blen) ; $l++) {
        my $v = $blen[$l];
        if($b <= $v){
            $vlen = $l;
            last;
        }
        $mask >>= 1;
    }
    if($vlen == 0){
        return $b & ($mask - 1);
    }
    $_[0]->Read($buff, $vlen);
    $buff .= "\0\0\0\0\0\0\0\0";
    
    my $value = unpack('Q', $buff);
    my $highpart = $b & ($mask - 1);
    return $value + ($highpart << ($vlen * 8));
}


sub ReadBoolean {
    my $buff;
    my $count = $_[1];
    my $checkall = $_[2];
    
    if($checkall){
        $_[0]->Read($buff, 1);
        my $all_defined = ord($buff);
        if($all_defined != 0){
            return (1)x$count;
        }
    }
    
    my @result = ();
    my $b = 0;
    my $mask = 0;
    
    for (my $i = 0 ; $i < $count ; $i++) {
        if($mask == 0){
            $_[0]->Read($buff, 1);
            $b = ord($buff);
            $mask = 0x80;
        }
        push(@result, ($b & $mask) != 0);
        $mask >>= 1;
    }
    return @result;
}


sub ReadPackInfo {
    my $buff;
    
    my $packpos = ReadUInt64($_[0]);
    my $numstreams = ReadUInt64($_[0]);
    print("Pack:$packpos,Num:$numstreams\n");
    
    $_[0]->Read($buff, 1);
    my $pid = ord($buff);
    
    my @packsizes;
    if($pid == 9){  # size
        for (my $i = 0 ; $i < $numstreams ; $i++) {
            push(@packsizes, ReadUInt64($_[0]));
        }
        $_[0]->Read($buff, 1);
        $pid = ord($buff);
        if($pid == 10){  # crc
            my @crcs;
            my @digestdefined = ReadBoolean($_[0], $numstreams, 1);
            foreach my $crcexist (@digestdefined) {
                if($crcexist){
                    push(@crcs, ReadUInt32($_[0]));
                }
            }
            $_[0]->Read($buff, 1);
            $pid = ord($buff);
        }
    }
    if($pid != 0) {  # end id expected
        return 0;
    }
    return 1;
}

sub findInBinPair {
    my @bindpairs = @{$_[0]};
    my $index = $_[1];
    
    for (my $i = 0; $i < scalar(@bindpairs); $i++) {
        if($bindpairs[$i] == $index){
            return $i;
        }
    }
    return -1;
}


sub ReadFolder {
    my $buff;
    my $totalin = 0;
    my $totalout = 0;
    my %out_folder = ();
    $out_folder{"packed_indices"} = ();
    $out_folder{"bindpairs"} = ();
    $out_folder{"coders"} = ();
    my %c = ();

    my $num_coders = ReadUInt64($_[0]);
    print("num_coders:$num_coders\n");
    
    for (my $i = 0; $i < $num_coders; $i++) {
        $_[0]->Read($buff, 1);
        my $b = ord($buff);
        my $methodsize = $b & 0xF;
        my $iscomplex = ($b & 0x10) == 0x10;
        my $hasattributes = ($b & 0x20) == 0x20;
        if($methodsize > 0){
           $_[0]->Read($buff, $methodsize);
           $c{"method"} = $buff;
        }
        else{
           $c{"method"} = "\0";
        }
        if($iscomplex){
            $c{"numinstreams"} = ReadUInt64($_[0]);
            $c{"numoutstreams"} = ReadUInt64($_[0]);
        }
        else{
            $c{"numinstreams"} = 1;
            $c{"numoutstreams"} = 1;
        }
        $totalin += $c{"numinstreams"};
        $totalout += $c{"numoutstreams"};
        if($hasattributes){
            my $proplen = ReadUInt64($_[0]);
            $_[0]->Read($buff, $proplen);
            $c{"properties"} = $buff;
        } 
        else {
            $c{"properties"} = undef;
        }      
        push(@{ $out_folder{"coders"} }, \%c);   
    }
    my $num_bindpairs = $totalout - 1;
    for (my $i = 0; $i < $num_bindpairs; $i++) {
        my @bond = (ReadUInt64($_[0]), ReadUInt64($_[0]));
        push(@{ $out_folder{"bindpairs"} }, @bond);
    }
    my $num_packedstreams = $totalin - $num_bindpairs;
    if($num_packedstreams == 1){
        for (my $i = 0; $i < $totalin; $i++) {
            if(findInBinPair(\@{ $out_folder{"bindpairs"} }, $i) < 0){
                push(@{ $out_folder{"packed_indices"} }, $i);
            }
        }
    }
    else{
        for (my $i = 0; $i < $num_packedstreams; $i++) {
            push(@{ $out_folder{"packed_indices"} }, ReadUInt64($_[0]));
        }
    }
    
    return %out_folder;
}

sub RetrieveCodersInfo{
    my $buff;
    my @folders = $_[1];

    $_[0]->Read($buff, 1);
    my $pid = ord($buff);
    
    if($pid != 0x0c){ # coders unpack size id expected
        return 0;
    }
    print("everything is ok until now($pid)\n");
    foreach my $folder (@folders) {
        $folder->{"unpacksizes"} = ();
        foreach my $c (@{ $folder->{"coders"} }) {
            for (my $i = 0 ; $i < $c->{"numoutstreams"} ; $i++) {
                push(@{ $folder->{"unpacksizes" } }, ReadUInt64($_[0]));
            }
        }
    }
    $_[0]->Read($buff, 1);
    $pid = ord($buff);

    if($pid == 0x0a){  #crc
        my $numfolders = scalar(@folders);
        print("num_folders:$numfolders\n");
        my @defined = ReadBoolean($_[0], $numfolders, 1);
        print(Dumper($defined[0]));
    }
    
}

sub ReadUnpackInfo {
    my $buff;
    
    $_[0]->Read($buff, 1);
    my $pid = ord($buff);
    
    if($pid != 0xb) {  # folder id expected
        return 0;
    }
    
    my $numfolders = ReadUInt64($_[0]);
    my @folders = ();
    
    $_[0]->Read($buff, 1);
    my $external = ord($buff);
    
    if($external == 0x00){
        for (my $i = 0 ; $i < $numfolders ; $i++) {
            my %folder = ReadFolder($_[0]);
            push(@folders, \%folder);
        }
    }
    RetrieveCodersInfo($_[0], @folders);
    return 1;
}


sub ReadStreamsInfo {
    my $buff;
    
    $_[0]->Read($buff, 1);
    my $pid = ord($buff);
    if($pid == 6){  # pack info
        return 0 unless ReadPackInfo($_[0]);
        $_[0]->Read($buff, 1);
        $pid = ord($buff);
    }
    if($pid == 7) {  # unpack info
        print("unpack info\n");
        return 0 unless ReadUnpackInfo($_[0]);
    }
    
    return 1;
}

#------------------------------------------------------------------------------
# Extract information from a 7z file
# Inputs: 0) ExifTool object reference, 1) dirInfo reference
# Returns: 1 on success, 0 if this wasn't a valid 7z file
sub Process7z($$)
{
    my ($et, $dirInfo) = @_;
    my $raf = $$dirInfo{RAF};
    my ($flags, $buff);
    
    return 0 unless $raf->Read($buff, 6) and $buff eq "7z\xbc\xaf\x27\x1c";
    
    $et->SetFileType();
    
    $raf->Read($buff, 2);
    my ($major_version, $minor_version) = unpack('cc', $buff);
    $et->FoundTag('MajorVersion', $major_version);
    $et->FoundTag('MinorVersion', $minor_version);
    
    $raf->Seek(4, 1);  # skip Start Header CRC
    
    $raf->Read($buff, 20);
    my ($nextheaderoffset, $nextheadersize) = unpack('QQx', $buff);
    print("$nextheaderoffset, $nextheadersize\n");
    
    $raf->Seek($nextheaderoffset, 1);  # going to next header offset
    $raf->Read($buff, 1);
    my $pid = ord($buff);
    if($pid == 1){  # normal header
        print("Normal Header\n");
    }
    elsif($pid == 23){  # encoded header
        print("Encoded Header\n");
        ReadStreamsInfo($raf);
    }else{  # Unknown header
        return 0;
    }
    
    return 1;
}


1;  # end

__END__

