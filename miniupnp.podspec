Pod::Spec.new do |spec|
  spec.name = "miniupnp"
  spec.summary = "Mini UPnP client"
  spec.homepage = 'http://miniupnp.free.fr/'
  spec.authors = "The MiniUPnP Authors"
  spec.license = { type: "BSD", file: "miniupnpc/LICENSE" }

  spec.version = "2.0.0.0"
  spec.source = {
      git: 'https://github.com/cpp-ethereum-ios/miniupnp.git',
      tag: "v#{spec.version}"
  }

  spec.platform = :ios
  spec.ios.deployment_target = '8.0'

  spec.prepare_command = <<-CMD
    build_for_ios() {
      build_for_architecture iphoneos armv7 arm-apple-darwin
      build_for_architecture iphonesimulator i386 i386-apple-darwin
      build_for_architecture iphoneos arm64 arm-apple-darwin
      build_for_architecture iphonesimulator x86_64 x86_64-apple-darwin
      create_universal_library
    }

    build_for_architecture() {
      PLATFORM=$1
      ARCH=$2
      HOST=$3
      SDKPATH=`xcrun -sdk $PLATFORM --show-sdk-path`
      PREFIX="build-ios/$ARCH"
      mkdir -p "$PREFIX"
      xcrun -sdk $PLATFORM make clean
      xcrun -sdk $PLATFORM make -j 16 install \
        PREFIX="$PREFIX" \
        CC=`xcrun -sdk $PLATFORM -find cc` \
        CFLAGS="-arch $ARCH -isysroot $SDKPATH" \
        LIBTOOL=`xcrun -sdk $PLATFORM -find libtool` \
        LDFLAGS="-arch $ARCH"
    }

    create_universal_library() {
      lipo -create -output build-ios/libminiupnpc.dylib \
        build-ios/{armv7,arm64,i386,x86_64}/usr/lib/libminiupnpc.dylib
    }

    cd miniupnpc
    build_for_ios
  CMD

  spec.source_files = "miniupnpc/build-ios/armv7/usr/include/**/*.h"
  spec.ios.vendored_libraries = "miniupnpc/build-ios/libminiupnpc.dylib"
end
