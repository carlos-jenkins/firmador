pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'ln -sf /usr/include/rapidjson'
        sh 'autoreconf -i'
        sh 'mingw32-configure'
        sh 'mingw32-make'
      }
    }
    stage('Archive') {
      steps {
        sh 'cp --remove-destination /usr/i686-w64-mingw32/sys-root/mingw/bin/{libgcc_s_sjlj-1,libgnutls-30,libstdc++-6,wxbase28u_gcc_custom,wxmsw28u_core_gcc_custom,libwinpthread-1,libgmp-10,libhogweed-4,libnettle-6,libp11-kit-0,libtasn1-6,zlib1,libjpeg-62,libpng16-16,libtiff-5,libffi-6,libmicrohttpd-12,libgcrypt-20,libgpg-error-0}.dll .'
        sh 'mingw-strip *.exe *.dll'
        archiveArtifacts '*.exe,*.manifest,*.dll'
      }
    }
  }
}
