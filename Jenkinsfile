pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'autoreconf -i'
        sh 'mingw32-configure'
        sh 'mingw32-make clean'
        sh 'mingw32-make'
      }
    }
    stage('Archive') {
      steps {
        sh 'ln -snf /usr/i686-w64-mingw32/sys-root/mingw/bin libs'
        archiveArtifacts 'firmador.exe,firmador.exe.manifest,libs/libgcc_s_sjlj-1.dll,libs/libgnutls-30.dll,libs/libstdc++-6,libs/wxbase28u_gcc_custom,libs/wxmsw28u_core_gcc_custom.dll,libs/libwinpthread-1.dll,libs/libgmp-10.dll,libs/libhogweed-4.dll,libs/libnettle-6.dll,libs/libp11-kit-0.dll,libs/libtasn1-6,libs/zlib1.dll,libs/libjpeg-62.dll,libs/libpng16-16.dll,libs/libtiff-5.dll,libs/libffi-6.dll'
      }
    }
  }
}