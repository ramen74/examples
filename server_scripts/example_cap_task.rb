#This is an example cap test to install image magick

 desc "Install ImageMagick and RMagick"
  task :install_rmagick, :roles => :app do

    # Upload the required files to /lcp/downloads
    run "mkdir -p /lcp/downloads"
    upload "upload/app_packages/rmagick", "/lcp/downloads", :via => :scp, :recursive => true

    # Install libpng
    sudo "rm -rf /lcp/downloads/rmagick/libpng-1.2.38"
    run "tar -xzf /lcp/downloads/rmagick/libpng-1.2.38.tar.gz -C /lcp/downloads/rmagick"
    sudo "cd /lcp/downloads/rmagick/libpng-1.2.38; ./configure"
    sudo "cd /lcp/downloads/rmagick/libpng-1.2.38; make"
    sudo "cd /lcp/downloads/rmagick/libpng-1.2.38; make install"

    # Install jpeg
    sudo "rm -rf /lcp/downloads/rmagick/jpeg-6b"
    run "tar -xzf /lcp/downloads/rmagick/jpegsrc.v6b.tar.gz -C /lcp/downloads/rmagick"
    sudo "cd /lcp/downloads/rmagick/jpeg-6b; ./configure --enable-shared"
    # The make command requires libtool, which is available with libpng
    run "cp -f /lcp/downloads/rmagick/libpng-1.2.38/libtool /lcp/downloads/rmagick/jpeg-6b"
    sudo "cd /lcp/downloads/rmagick/jpeg-6b; make"
    # The make install command requires that /usr/local/man/man1 exists
    sudo "mkdir -p /usr/local/man/man1"
    sudo "cd /lcp/downloads/rmagick/jpeg-6b; make install"

    # Install ImageMagick
    sudo "rm -rf /lcp/downloads/rmagick/ImageMagick-6.5.4-6"
    run "tar -xzf /lcp/downloads/rmagick/ImageMagick.tar.gz -C /lcp/downloads/rmagick"
    sudo "cd /lcp/downloads/rmagick/ImageMagick-6.5.4-6; ./configure"
    sudo "cd /lcp/downloads/rmagick/ImageMagick-6.5.4-6; make"
    sudo "cd /lcp/downloads/rmagick/ImageMagick-6.5.4-6; make install"
    sudo "/sbin/ldconfig"

    # Install RMagick
    sudo "export PATH=/usr/local/bin:$PATH; " +
      "/usr/local/bin/gem list -i rmagick -v 2.13.1 > /dev/null " +
      "|| /usr/local/bin/gem install -l /lcp/downloads/rmagick/rmagick-2.13.1"
  end

