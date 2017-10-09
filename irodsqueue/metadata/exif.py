import exifread

def extract_metadata(path, **kwargs):

    meta_str = ""

    if path.endswith('.tif'):
        with open(path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
            for key, value in tags.items():
                if key not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                    meta_str += "{};{};;".format(key, value)

    return meta_str
