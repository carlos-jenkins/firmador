pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'autoreconf -i'
        sh 'mingw32-configure CXXFLAGS=-Wno-unused-local-typedefs'
        sh 'mingw32-make clean'
        sh 'mingw32-make'
      }
    }
  }
}