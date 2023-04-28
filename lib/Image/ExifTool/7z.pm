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
    return 1;
}


1;  # end

__END__

